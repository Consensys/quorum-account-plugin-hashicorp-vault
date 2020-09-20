package integration

import (
	"encoding/json"
	"log"
)

// stdioListener listens to stdio for clef UI requests and writes approvals.
// It blocks so should be started in a separate goroutine.
func stdioListener(stdio stdioPipes) {
	log.Println("starting clef stdio listener")
	defer log.Println("stopped clef stdio listener")

	jsonDecoder := json.NewDecoder(stdio.stdoutPipe)
	var req map[string]interface{}

	for {
		if err := jsonDecoder.Decode(&req); err != nil {
			log.Printf("[ERROR] stdioListener: err=%v", err)
		}

		method, ok := req["method"]
		if !ok {
			log.Printf("cannot handle received stdio %v", req)
		}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
		}

		log.Printf("Received clef UI request: id=%v, method=%v", req["id"], method)
		switch method {
		case "ui_approveTx":
			p := req["params"].([]interface{})
			pm := p[0].(map[string]interface{})
			txArgs := pm["transaction"]
			resp["result"] = SignTxResponse{Transaction: txArgs, Approved: true}
		case "ui_approveSignData":
			resp["result"] = ApprovalResponse{Approved: true}
		case "ui_approveListing":
			p := req["params"].([]interface{})
			pm := p[0].(map[string]interface{})
			accts := pm["accounts"]
			resp["result"] = ListingResponse{Accounts: accts}
		case "ui_approveNewAccount":
			resp["result"] = ApprovalResponse{Approved: true}
		case "ui_showError", "ui_showInfo":
			log.Printf("showing: %v", req["params"])
			resp["result"] = ""
		case "ui_onApprovedTx", "ui_onSignerStartup":
			resp["result"] = ""
		case "ui_onInputRequired":
			resp["result"] = InputResponse{Text: ""}
		}

		jsonResp, err := json.Marshal(resp)

		n, err := stdio.stdinPipe.Write(jsonResp)
		if err != nil {
			log.Printf("[ERROR] stdioListener: unable to write to stdin, err=%v", err)
		} else if n == 0 {
			log.Printf("[ERROR] stdioListener: no data written to stdin")
		}
	}
}

type SignTxResponse struct {
	Transaction interface{}
	Approved    bool
}

type ListingResponse struct {
	Accounts interface{}
}

type ApprovalResponse struct {
	Approved bool
}

type InputResponse struct {
	Text string
}
