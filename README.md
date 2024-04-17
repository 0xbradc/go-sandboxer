# go-sandboxer
Local process sandboxer built in Go.


## Compiling/Running
1. Make sure you have Go installed on your system ([here](https://go.dev/dl/)). 

2. Install dependencies: 
```
 $ go install github.com/hjr265/ptrace.go/ptrace@latest
```

3. Navigate to the directory with the desired Go (*.go) file.

4. Enter `go run sandboxer.go` into a terminal.


## Docker Stuff
- I had problems with getting extensions to work on VS Code, so I followed [this workaround](https://github.com/microsoft/vscode-remote-release/issues/8967#issuecomment-1873199481) to get things running correctly (I was missing some dev features from this).
