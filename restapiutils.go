package snetutils

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sonnt85/gosutils/sutils"
)

//{
//  "result": {
//    "id":"2d4d028de3015345da9420df5514dad0",
//    "type":"A",
//    "name":"blog.example.com",
//    "content":"2.6.4.5",
//    "proxiable":true,
//    "proxied":false,
//    "ttl":1,
//    "priority":0,
//    "locked":false,
//    "zone_id":"cd7d068de3012345da9420df9514dad0",
//    "zone_name":"example.com",
//    "modified_on":"2014-05-28T18:46:18.764425Z",
//    "created_on":"2014-05-28T18:46:18.764425Z"
//  },
//  "success": true,
//  "errors": [],
//  "messages": [],
//  "result_info": {
//    "page": 1,
//    "per_page": 20,
//    "count": 1,
//    "total_count": 200
//  }
//}

type HAErrorCode struct {
	Code     int
	Messages string
}

type HA map[string]interface{}

type HAMessages map[string]interface{}

type HAResult map[string]interface{}

type HAResultInfo map[string]interface{}

type HAResponseCommon struct { //            error    sucess
	Result   HAResult      `json:"result"`  //nil
	Success  bool          `json:"success"` //false   true
	Errors   []HAErrorCode `json:"errors"`
	Messages []HAMessages  `json:"messages"`
}

type HAErrorResponse struct {
	HAResponseCommon
}

type HASuccessResponse struct {
	HAResponseCommon
	Result_info HAResultInfo `json:"result_info"`
}

func HABuildErrorResponse(errors []HAErrorCode, messages []HAMessages) (respose *HAErrorResponse) {
	respose = new(HAErrorResponse)
	//	respose.Result = HAResult{}
	respose.Result = nil

	respose.Success = false
	if len(errors) == 0 {
		respose.Errors = append(respose.Errors, HAErrorCode{1003, "Invalid or missing something"})
	} else {
		respose.Errors = errors
	}

	if len(messages) != 0 {
		respose.Messages = messages
	} else {
		respose.Messages = []HAMessages{}
	}
	respose.Messages = append(respose.Messages, HAMessages{"run_at": fmt.Sprintf("%s", time.Now().Format(time.StampMilli))})
	//	log.Printf("%+v", *respose)
	return respose
}

func HABuildSuccessRespone(result HAResult, messages []HAMessages, result_info ...HAResultInfo) (respose *HASuccessResponse) {
	//	result={id:2d4d028de3015345da9420df5514dad0}, ,, , ){
	respose = new(HASuccessResponse)
	respose.Success = true
	respose.Errors = []HAErrorCode{}
	if len(messages) != 0 {
		respose.Messages = messages
	} else {
		respose.Messages = []HAMessages{}
	}
	respose.Messages = append(respose.Messages, HAMessages{"run_at": fmt.Sprintf("%s", time.Now().Format(time.StampMilli))})

	if len(result) != 0 {
		respose.Result = result
	} else {
		respose.Result = HAResult{}
	}

	if len(result_info) != 0 {
		respose.Result_info = result_info[0]
	} else {
		respose.Result_info = HAResultInfo{}
	}
	if _, ok := respose.Result_info["id"]; !ok {
		respose.Result_info["id"] = sutils.IDGenerate()
	}

	return respose
}

func HABuildErrorResponseStr(errors []HAErrorCode, messages []HAMessages) (respose string) {
	haerror := HABuildErrorResponse(errors, messages)
	resposeb, _ := json.Marshal(haerror)
	return string(resposeb)
}

func HABuildSuccessResponeStr(result HAResult, messages []HAMessages, result_info ...HAResultInfo) (respose string) {
	hasuccess := HABuildSuccessRespone(result, messages, result_info...)
	resposeb, _ := json.Marshal(hasuccess)
	return string(resposeb)
}
