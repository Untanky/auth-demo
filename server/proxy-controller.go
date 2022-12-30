package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
    "net/http/httputil"
)

const proxyHost = "localhost:5173"

var httpClient = http.Client{}

func ProxyRequest(c *gin.Context) {
    director := func(req *http.Request) {
        req.URL.Scheme = "http"
        req.URL.Host = proxyHost
    }
    proxy := &httputil.ReverseProxy{Director: director}
    proxy.ServeHTTP(c.Writer, c.Request)
}
