build:
	go build -o ruler ruler.go

run:
	go run ruler.go

compile:
	# 32-bit
	# Linux
	GOOS=linux GOARCH=386 go build -o ruler-linux86
	sha256sum  ruler-linux86
	# Windows
	GOOS=windows GOARCH=386 go build -o ruler-win86.exe
	sha256sum  ruler-win86.exe

	# 64-bit
	# Linux
	GOOS=linux GOARCH=amd64 go build -o ruler-linux64
	sha256sum  ruler-linux64
	# Windows
	GOOS=windows GOARCH=amd64 go build -o ruler-win64.exe
	sha256sum  ruler-win64.exe
 	# OSX
	GOOS=darwin GOARCH=amd64 go build -o ruler-osx64
	sha256sum  ruler-osx64

	# ARM 64-bit
	# 64-bit
	# Linux
	GOOS=linux GOARCH=arm64 go build -o ruler-linux-arm64
	sha256sum  ruler-linux-arm64
	# Windows
	GOOS=windows GOARCH=arm64 go build -o ruler-win-arm64.exe
	sha256sum  ruler-win-arm64.exe
 	# OSX
	GOOS=darwin GOARCH=arm64 go build -o ruler-osx-arm64
	sha256sum  ruler-osx-arm64
