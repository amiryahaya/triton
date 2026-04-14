Generate hello.exe for tests:

  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o hello.exe hello.go

Where hello.go is:

  package main
  func main() { println("hello") }

The 2-3MB PE binary is checked in to keep tests hermetic.
