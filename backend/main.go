package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"kuberule/backend/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "18081"
	}

	fmt.Printf("Starting server on port %s\n", port)

	mux := http.NewServeMux()
	api.SetupRoutes(mux)

	serverAddress := ":" + port
	server := &http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
