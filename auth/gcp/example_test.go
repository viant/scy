package gcp_test

import (
	"context"
	"fmt"
	"github.com/viant/scy/auth/gcp"
	"github.com/viant/scy/auth/gcp/client"
	"io/ioutil"
	"log"
)

func ExampleService_IDClient() {
	srv := gcp.New(client.NewScy())
	ctx := context.Background()
	audience := "https://us-central1-myProject.cloudfunctions.net/MyCloudFunction"
	httpClient, err := srv.IDClient(ctx, audience)
	//Call secured cloud function
	resp, err := httpClient.Get(audience)
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CF response: %s\n", data)
}
