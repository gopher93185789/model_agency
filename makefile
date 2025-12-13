TAILWIND = npx @tailwindcss/cli
TAILWIND_INPUT = ./globals.css
TAILWIND_OUTPUT = ./static/dist.css

TEMPL = templ
GOFLAGS = -ldflags="-s -w" -trimpath

.PHONY: run build deps css gen clean

run:
	@$(TEMPL) generate
	@$(TAILWIND) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)
	@go run .

build: 
	@$(TEMPL) generate
	@$(TAILWIND) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)
	@go build $(GOFLAGS) .

css:
	@$(TAILWIND) --watch -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)

gen:
	@$(TEMPL) generate --watch

deps:
	@echo "Installing templ..."
	@go install github.com/a-h/templ/cmd/templ@latest
	@go install github.com/air-verse/air@latest
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