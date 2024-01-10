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

//{
//  "result": null,
//  "success": false,
//  "errors": [{Code: 1006, Messages: "Client is offline"}],
//  "messages": [],
//}

// HAErrorCode represents an error code along with a message.
type HAErrorCode struct {
	Code     int
	Messages string
}

func HABuildErrorCode(code int, msg string) HAErrorCode {
	return HAErrorCode{code, msg}
}

// HA is a type alias representing a map with string keys and interface{} values.
type HA map[string]interface{}

// HAMessages is a type alias representing a map with string keys and interface{} values,
// typically used for representing messages in the response.
type HAMessages map[string]interface{}

// HAResult is a type alias representing a map with string keys and interface{} values,
// typically used for representing the result of an operation in the response.
type HAResult map[string]interface{}

// HAResultInfo is a type alias representing a map with string keys and interface{} values,
// often used for representing additional information about the result.
type HAResultInfo map[string]interface{}

// HAResponseCommon is a common structure for both error and success responses.
type HAResponseCommon struct {
	Result   HAResult      `json:"result"`   // Result of the operation, nil for error
	Success  bool          `json:"success"`  // Indicates success or failure (false/true)
	Errors   []HAErrorCode `json:"errors"`   // List of error codes and messages
	Messages []HAMessages  `json:"messages"` // List of messages
}

// HAErrorResponse represents an error response containing common response fields.
type HAErrorResponse struct {
	HAResponseCommon
}

// HASuccessResponse represents a success response containing common response fields
// along with additional result information.
type HASuccessResponse struct {
	HAResponseCommon
	Result_info HAResultInfo `json:"result_info"` // Additional result information
}

// HABuildErrorResponse constructs an error response based on provided error codes and messages.
// Parameters:
//
//	struct HAErrorCode { Code int; Messages string }
//	errors: []HAErrorCode - List of error codes and messages
//
//	messages: []HAMessages (map[string]interface{}) - List of messages
//
// Returns:
//
//	response: *HAErrorResponse - Constructed error response
func HABuildErrorResponse(errors []HAErrorCode, messages []HAMessages) (response *HAErrorResponse) {
	respose := new(HAErrorResponse)
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
	return respose
}

// HABuildSuccessRespone constructs a success response with the provided result, messages,
// and optional result information.
// Parameters:
//
//	result: HAResult (map[string]interface{})- Result of the operation
//	messages: []HAMessages (map[string]interface{}) - List of messages
//	result_info: ...HAResultInfo (map[string]interface{}) - Optional additional result information
//
// Returns:
//
//	response: *HASuccessResponse - Constructed success response
func HABuildSuccessRespone(result HAResult, messages []HAMessages, result_info ...HAResultInfo) (response *HASuccessResponse) {
	respose := new(HASuccessResponse)
	respose.Success = true
	respose.Errors = []HAErrorCode{}
	if len(messages) != 0 {
		respose.Messages = messages
	} else {
		respose.Messages = []HAMessages{}
	}
	respose.Messages = append(respose.Messages, HAMessages{"run_at": time.Now().Format(time.StampMilli)})

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

// HABuildErrorResponseStr constructs an error response as a JSON string based on provided error codes and messages.
// Parameters:
//
//	errors: []HAErrorCode (type HAErrorCode struct {
//	  Code     int
//	  Messages string
//	}) - List of error codes and messages
//	messages: []HAMessages (map[string]interface{}) - List of messages
//
// Returns:
//
//	response: string - Constructed error response as a JSON string
func HABuildErrorResponseStr(errors []HAErrorCode, messages []HAMessages) (response string) {
	haerror := HABuildErrorResponse(errors, messages)
	resposeb, _ := json.Marshal(haerror)
	return string(resposeb)
}

// HABuildSuccessResponeStr constructs a success response as a JSON string with the provided result, messages,
// and optional result information.
// Parameters:
//
//	result: HAResult (map[string]interface{})- Result of the operation
//	messages: []HAMessages (map[string]interface{}) - List of messages
//	result_info: ...HAResultInfo (map[string]interface{}) - Optional additional result information
//
// Returns:
//
//	response: string - Constructed success response as a JSON string
func HABuildSuccessResponeStr(result HAResult, messages []HAMessages, result_info ...HAResultInfo) (response string) {
	hasuccess := HABuildSuccessRespone(result, messages, result_info...)
	resposeb, _ := json.Marshal(hasuccess)
	return string(resposeb)
}
