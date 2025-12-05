TAILWIND = npx @tailwindcss/cli
TAILWIND_INPUT = ./globals.css
TAILWIND_OUTPUT = ./static/dist.css

TEMPL = templ
GOFLAGS = -ldflags="-s -w" -trimpath

.PHONY: run build deps css gen clean

run: css gen
	@go run .

build: css gen
	@go build $(GOFLAGS) .

css:
	@$(TAILWIND) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)

gen:
	@$(TEMPL) generate

deps:
	@echo "Installing templ..."
	@go install github.com/a-h/templ/cmd/templ@latest
	@echo "Installing tailwind..."
	@npm install tailwindcss @tailwindcss/cli

clean:
	@rm -rf node_modules
	@rm -f

escape: 
	@go build -gcflags "-m" . > escape.txt 2>&1
	@grep -i 'escapes to heap' escape.txt > escapes.txt
	@rm -f escape.txt model_agency
asm: 
	@go build -gcflags "-S" . > main.asm 2>&1
	@rm -f model_agency