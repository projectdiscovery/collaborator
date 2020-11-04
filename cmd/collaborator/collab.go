package main

import (
	"log"

	"github.com/projectdiscovery/collaborator"
)

func main() {
	burpcollab := collaborator.NewBurpCollaborator()
	burpcollab.AddBIID("xxxxxx")
	err := burpcollab.Poll()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v\n", burpcollab.RespBuffer)
}
