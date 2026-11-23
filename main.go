package main

import "log"

func main() {
	// run 返回时日志已关闭，标准库 log 已恢复为 stderr；非零退出码让编排系统感知启动失败。
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
