package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

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
	err := http.ListenAndServe(serverAddress, mux)
	if err != nil {
		log.Fatal(err)
	}
}
