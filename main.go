package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pages"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

//go:embed static/**
var 静态文件系统 embed.FS

const 会话Cookie名称 string = "duke_dennis"
const 会话过期时间 = 6 * time.Hour
const 中间件令牌 = "token"

type 服务器上下文 struct {
	数据库 *pgxpool.Pool
	存储  *会话存储
}

func 新建服务器上下文(数据库 *pgxpool.Pool) *服务器上下文 {
	return &服务器上下文{
		数据库: 数据库,
		存储: &会话存储{
			互斥锁: sync.RWMutex{},
			用户:  make(map[string]存储载荷),
		},
	}
}

/*****************************************************
 *                  会话存储                    *
 *****************************************************/
type 存储载荷 struct {
	用户ID   uuid.UUID
	角色     string
	过期时间   time.Time
	个人资料网址 string
}

type 会话存储 struct {
	互斥锁 sync.RWMutex
	用户  map[string]存储载荷
}

func (s *会话存储) 获取(键 string) (存 存储载荷, 错误 error) {
	s.互斥锁.RLock()
	defer s.互斥锁.RUnlock()

	存, 成功 := s.用户[键]
	if !成功 {
		return 存, fmt.Errorf("没有匹配给定键的值")
	}

	return 存, nil
}

func (s *会话存储) 设置(键 string, 值 存储载荷) {
	s.互斥锁.Lock()
	s.用户[键] = 值
	s.互斥锁.Unlock()
}

func (s *会话存储) 删除(键 string) {
	s.互斥锁.Lock()
	delete(s.用户, 键)
	s.互斥锁.Unlock()
}

/***********************************************
 *                  辅助函数                    *
 ***********************************************/
func 用JSON响应[P any](w http.ResponseWriter, 代码 int, 载荷 P) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(代码)
	错误 := json.NewEncoder(w).Encode(载荷)
	if 错误 != nil {
		log.Printf("编码JSON响应时出错: %v", 错误)
		return
	}
}

func 哈希密码(密码 string) (哈希 []byte, 错误 error) {
	return bcrypt.GenerateFromPassword([]byte(密码), bcrypt.DefaultCost)
}

/**************************************************
 *                  中间件                    *
 **************************************************/
/*
# 轻松获取用户信息的方法:

	信息, 错误 := s.存储.获取(w.Header().Get(中间件令牌))
	if 错误 != nil {
		return
	}
*/
func (s *服务器上下文) 认证中间件(下一个 http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			会话ID string
		)

		cookie, 错误 := r.Cookie(会话Cookie名称)
		if 错误 != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusPermanentRedirect)
			return
		}
		会话ID = cookie.Value

		存, 错误 := s.存储.获取(会话ID)
		if 错误 != nil {
			http.Redirect(w, r, "/login", http.StatusPermanentRedirect)
			return
		}

		if time.Now().After(存.过期时间) {
			s.存储.删除(会话ID)
			http.Redirect(w, r, "/login", http.StatusPermanentRedirect)
			return
		}

		r.Header.Set(中间件令牌, cookie.Value)
		下一个.ServeHTTP(w, r)
	}
}

/********************************************
 *                  认证                    *
 ********************************************/
// 不允许注册为教师因为我们会手动提升他们
func (s *服务器上下文) 注册(w http.ResponseWriter, r *http.Request) {
	上下文 := r.Context()

	// if 错误 := r.ParseMultipartForm(3e+7); 错误 != nil {
	// 	http.Error(w, "解析表单失败", http.StatusBadRequest)
	// 	return
	// }

	var (
		学校ID     = r.FormValue("school_id")
		姓名       = r.FormValue("name")
		密码       = r.FormValue("password")
		角色       = r.FormValue("role")
		有文件      = false
		个人资料图片网址 = ""
		已批准      = false
	)
	// 图片文件, 头, 错误 := r.FormFile("profile_image")
	// if 错误 == nil {
	// 	有文件 = true
	// }
	// defer 图片文件.Close()

	if 学校ID == "" || 姓名 == "" || 密码 == "" || 角色 == "" {
		http.Error(w, "学校ID、姓名、密码和角色是必需的", http.StatusBadRequest)
		return
	}

	if 角色 != "model" && 角色 != "fotograaf" {
		http.Error(w, "角色必须是以下之一: model, fotograaf", http.StatusBadRequest)
		return
	}

	// 来自任务提供者的电子邮件:
	// 好问题！不，我确实是指教师必须批准模特的申请。
	if 角色 == "fotograaf" {
		已批准 = true
	}

	密码哈希, 错误 := 哈希密码(密码)
	if 错误 != nil {
		log.Printf("密码哈希失败: %v", 错误)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}

	// 解析并上传到r2然后返回url
	if 有文件 {
		// 上传
	}

	查询 := `
		WITH user_i AS (
			INSERT INTO app_users (role, school_id, name, password_hash) 
			VALUES ($1, $2, $3, $4) 
			RETURNING id
		)
			INSERT INTO profile (user_id, approved, profile_image_url) 
			SELECT id, $5, $6
			FROM user_i
			RETURNING id
	`

	_, 错误 = s.数据库.Exec(上下文, 查询,
		角色,
		学校ID,
		姓名,
		string(密码哈希),
		已批准,
		个人资料图片网址,
	)

	if 错误 != nil {
		log.Printf("数据库插入失败: %v", 错误)
		if 错误.Error() == "duplicate key value violates unique constraint" {
			http.Error(w, "该学校ID已被使用", http.StatusConflict)
			return
		}

		http.Error(w, "创建用户失败", http.StatusInternalServerError)
		return
	}

	// 也许我们可以使用查询参数模态框重定向到主页
	// 如果不为空可以显示一个模态弹窗说"等待教师批准您的个人资料"以获得更好的用户体验
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *服务器上下文) 登录(w http.ResponseWriter, r *http.Request) {
	上下文 := r.Context()

	if 错误 := r.ParseForm(); 错误 != nil {
		http.Error(w, "解析表单失败", http.StatusBadRequest)
		return
	}

	学号 := r.FormValue("stunum")
	密码 := r.FormValue("password")

	if 学号 == "" || 密码 == "" {
		http.Error(w, "学号和密码是必需的", http.StatusBadRequest)
		return
	}

	var (
		ID   uuid.UUID
		密码哈希 []byte
		角色   string
		查询   = `
		SELECT id, password_hash, role 
		FROM app_users 
		WHERE school_id=$1 
		`
	)

	错误 := s.数据库.QueryRow(上下文, 查询, 学号).Scan(&ID, &密码哈希, &角色)
	if 错误 != nil {
		log.Printf("数据库查询失败: %v", 错误)
		http.Error(w, "无效的凭证", http.StatusUnauthorized)
		return
	}

	if 错误 := bcrypt.CompareHashAndPassword(密码哈希, []byte(密码)); 错误 != nil {
		http.Error(w, "无效的凭证", http.StatusUnauthorized)
		return
	}

	var 缓冲 = make([]byte, 12)
	_, 错误 = rand.Read(缓冲)
	if 错误 != nil {
		log.Printf("生成会话ID失败: %v", 错误)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}
	会话ID := hex.EncodeToString(缓冲)
	过期时间 := time.Now().Add(会话过期时间)

	s.存储.设置(会话ID, 存储载荷{
		用户ID: ID,
		角色:   角色,
		过期时间: 过期时间,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     会话Cookie名称,
		Value:    会话ID,
		Expires:  过期时间,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	// 登录成功后重定向到概览页面
	http.Redirect(w, r, "/overview", http.StatusSeeOther)
}

func (s *服务器上下文) 登出(w http.ResponseWriter, r *http.Request) {
	s.存储.删除(中间件令牌)
	http.SetCookie(w, &http.Cookie{
		Name:     会话Cookie名称,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
}

/*********************************************
 *                  页面                    *
 *********************************************/
func (s *服务器上下文) 概览处理器(w http.ResponseWriter, r *http.Request) {
	var (
		页面 templ.Component
	)

	存, 错误 := s.存储.获取(w.Header().Get(中间件令牌))
	if 错误 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch 存.角色 {
	case "docent":
		页面 = pages.Docent()
	case "model":
		页面 = pages.Model()
	case "fotograaf":
		页面 = pages.Fotograaf()
	default:
		http.Redirect(w, r, "/", http.StatusPermanentRedirect)
		return
	}

	root(页面).Render(r.Context(), w)
}

/*********************************************
 *                  入口                    *
 *********************************************/
func main() {
	路由器 := http.NewServeMux()
	连接, 错误 := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if 错误 != nil {
		panic(错误)
	}
	服务上下文 := 新建服务器上下文(连接)
	// 接口
	路由器.HandleFunc("POST /api/login", 服务上下文.登录)
	路由器.HandleFunc("POST /api/signup", 服务上下文.注册)
	路由器.HandleFunc("POST /api/logout", 服务上下文.认证中间件(服务上下文.登出))

	// 页面
	路由器.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { root(pages.Home()).Render(r.Context(), w) })
	路由器.HandleFunc("GET /overview", 服务上下文.认证中间件(服务上下文.概览处理器))
	静态子文件系统, _ := fs.Sub(静态文件系统, "static")
	路由器.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(静态子文件系统)))

	// 认证页面
	路由器.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { root(pages.Login()).Render(r.Context(), w) })
	路由器.HandleFunc("GET /signup", func(w http.ResponseWriter, r *http.Request) { root(pages.Signup()).Render(r.Context(), w) })

	log.Println("服务器监听在 http://localhost:42069")
	错误 = http.ListenAndServe(":42069", 路由器)
	if 错误 != nil {
		log.Fatalf("启动服务器失败: %v", 错误)
	}
}
