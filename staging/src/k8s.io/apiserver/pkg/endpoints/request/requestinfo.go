/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package request

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/api/validation/path"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metainternalversionscheme "k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/klog/v2"
)

// LongRunningRequestCheck is a predicate which is true for long-running http requests.
type LongRunningRequestCheck func(r *http.Request, requestInfo *RequestInfo) bool

type RequestInfoResolver interface {
	NewRequestInfo(req *http.Request) (*RequestInfo, error)
}

// RequestInfo holds information parsed from the http.Request
type RequestInfo struct {
	// IsResourceRequest indicates whether or not the request is for an API resource or subresource
	IsResourceRequest bool
	// Path is the URL path of the request
	Path string
	// Verb is the kube verb associated with the request for API requests, not the http verb.  This includes things like list and watch.
	// for non-resource requests, this is the lowercase http verb
	Verb string

	APIPrefix  string
	APIGroup   string
	APIVersion string
	Namespace  string
	// Resource is the name of the resource being requested.  This is not the kind.  For example: pods
	Resource string
	// Subresource is the name of the subresource being requested.  This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	Subresource string
	// Name is empty for some verbs, but if the request directly indicates a name (not in body content) then this field is filled in.
	Name string
	// Parts are the path parts for the request, always starting with /{resource}/{name}
	Parts []string
}

// specialVerbs contains just strings which are used in REST paths for special actions that don't fall under the normal
// CRUDdy GET/POST/PUT/DELETE actions on REST objects.
// TODO: find a way to keep this up to date automatically.  Maybe dynamically populate list as handlers added to
// master's Mux.
var specialVerbs = sets.NewString("proxy", "watch")

// specialVerbsNoSubresources contains root verbs which do not allow subresources
var specialVerbsNoSubresources = sets.NewString("proxy")

// namespaceSubresources contains subresources of namespace
// this list allows the parser to distinguish between a namespace subresource, and a namespaced resource
var namespaceSubresources = sets.NewString("status", "finalize")

// NamespaceSubResourcesForTest exports namespaceSubresources for testing in pkg/master/master_test.go, so we never drift
var NamespaceSubResourcesForTest = sets.NewString(namespaceSubresources.List()...)

type RequestInfoFactory struct {
	APIPrefixes          sets.String // without leading and trailing slashes
	GrouplessAPIPrefixes sets.String // without leading and trailing slashes
}

// TODO write an integration test against the swagger doc to test the RequestInfo and match up behavior to responses
// NewRequestInfo returns the information from the http request.  If error is not nil, RequestInfo holds the information as best it is known before the failure
// It handles both resource and non-resource requests and fills in all the pertinent information for each.
// Valid Inputs:
// Resource paths
// /apis/{api-group}/{version}/namespaces
// /api/{version}/namespaces
// /api/{version}/namespaces/{namespace}
// /api/{version}/namespaces/{namespace}/{resource}
// /api/{version}/namespaces/{namespace}/{resource}/{resourceName}
// /api/{version}/{resource}
// /api/{version}/{resource}/{resourceName}
//
// Special verbs without subresources:
// /api/{version}/proxy/{resource}/{resourceName}
// /api/{version}/proxy/namespaces/{namespace}/{resource}/{resourceName}
//
// Special verbs with subresources:
// /api/{version}/watch/{resource}
// /api/{version}/watch/namespaces/{namespace}/{resource}
//
// NonResource paths
// /apis/{api-group}/{version}
// /apis/{api-group}
// /apis
// /api/{version}
// /api
// /healthz
// /
func (r *RequestInfoFactory) NewRequestInfo(req *http.Request) (*RequestInfo, error) {
	// start with a non-resource request until proven otherwise
	requestInfo := RequestInfo{
		IsResourceRequest: false,
		Path:              req.URL.Path,
		Verb:              strings.ToLower(req.Method),
	}

	// 分割path信息
	currentParts := splitPath(req.URL.Path)
	// currentParts 小于3是说明是non-resource请求, 因为自愿请求的路径
	// 最小值是/api/{version}/{resource}
	if len(currentParts) < 3 {
		// return a non-resource request
		return &requestInfo, nil
	}

	// 分割后的path数量大于3时, 会存在两种情况
	// 1. resource request
	// 2. non-resource request
	// 当path信息数组第一个信息不包含api prefix时, 则是一个non-resource request
	if !r.APIPrefixes.Has(currentParts[0]) {
		// return a non-resource request
		return &requestInfo, nil
	}
	// 解析出 api prefix
	requestInfo.APIPrefix = currentParts[0]
	// 去除已经解析的api prefix, 保留后续的部分
	currentParts = currentParts[1:]

	// 解析 api group
	// GrouplessAPIPrefixes 一般是 /api 这个前缀
	// 已经解析出的requestInfo.APIPrefix不存在 groupless api prefix中,
	// 说明request请求是一个属于api group的请求
	if !r.GrouplessAPIPrefixes.Has(requestInfo.APIPrefix) {
		// one part (APIPrefix) has already been consumed, so this is actually "do we have four parts?"
		// currentParts 小于3, 但是api group的路径去除api prefix后都是大于等于3的, 因此应该是api group 的请求
		// 不包含api group 说明是一个non-resource request
		if len(currentParts) < 3 {
			// return a non-resource request
			return &requestInfo, nil
		}

		// 解析出api group
		requestInfo.APIGroup = currentParts[0]
		// 去除已经解析的api group, 保留后续的部分
		currentParts = currentParts[1:]
	}

	// 到这里可以确定是一个资源请求
	requestInfo.IsResourceRequest = true
	// 资源请求一定包含api version, 区别在于 /{api-group}/{version} 和 /{version} 两种情况
	// 而/{api-group}/{version}在前面已经处理, 所以这里可以安全的提取 api version
	requestInfo.APIVersion = currentParts[0]
	// 去除已经解析的api version, 保留后续的部分
	currentParts = currentParts[1:]

	// 到目前为止, 已经处理了如下情况的请求
	// Resource paths:
	// 属于api-group的资源请求
	// /apis/{api-group}/{version}/namespaces

	// 不属于api-group的资源请求
	// /api/{version}/namespaces
	// /api/{version}/namespaces/{namespace}
	// /api/{version}/namespaces/{namespace}/{resource}
	// /api/{version}/namespaces/{namespace}/{resource}/{resourceName}
	// /api/{version}/{resource}
	// /api/{version}/{resource}/{resourceName}

	// NonResource paths
	// 属于api-group的非资源请求
	// /apis/{api-group}/{version}
	// /apis/{api-group}
	// 其他情况的非资源请求
	// /apis
	// /api/{version}
	// /api
	// /healthz
	// /

	// 因此还剩下 Special verbs 情况没有处理.

	// handle input of form /{specialVerb}/*
	// 处理 specialVerbs, specialVerbs 包含两种情况
	// 1. proxy
	// 2. watch
	if specialVerbs.Has(currentParts[0]) {
		// 对于specialVerbs来说, 剩余的path信息应该>=2, 例如/api/{version}/watch/{resource}
		// 在提取了 APIPrefix, APIVersion 后, 至少还剩余 /watch/{resource}
		if len(currentParts) < 2 {
			return &requestInfo, fmt.Errorf("unable to determine kind and namespace from url, %v", req.URL)
		}

		// 提取verb
		requestInfo.Verb = currentParts[0]
		// 去除已经解析的verb, 保留后续的部分
		currentParts = currentParts[1:]

	} else {
		// 如果不是 specialVerbs, 则根据 http request method语义来定义 veb, 具体如下
		switch req.Method {
		case "POST":
			requestInfo.Verb = "create"
		case "GET", "HEAD":
			requestInfo.Verb = "get"
		case "PUT":
			requestInfo.Verb = "update"
		case "PATCH":
			requestInfo.Verb = "patch"
		case "DELETE":
			requestInfo.Verb = "delete"
		default:
			// 未定义的情况 verb 为空
			requestInfo.Verb = ""
		}
	}

	// URL forms: /namespaces/{namespace}/{kind}/*, where parts are adjusted to be relative to kind
	// 到这里对于所有的请求path来说, 还剩下是否包含namespace的情况
	if currentParts[0] == "namespaces" {
		if len(currentParts) > 1 {
			// 提取namespace
			requestInfo.Namespace = currentParts[1]

			// if there is another step after the namespace name and it is not a known namespace subresource
			// move currentParts to include it as a resource in its own right
			// namespace后面还有path信息, 并且path不是namespace subresource, 则
			// /namespaces/{namespace}/{resource}/{resourceName} -> /namespaces/{namespace}/{resourceName}
			if len(currentParts) > 2 && !namespaceSubresources.Has(currentParts[2]) {
				currentParts = currentParts[2:]
			}
		}
	} else {
		// namespace 为空
		requestInfo.Namespace = metav1.NamespaceNone
	}

	// parsing successful, so we now know the proper value for .Parts
	// 到这里路径解析完成, 已经提取出了
	// APIPrefix
	// APIGroup (如果存在)
	// APIVersion
	// Verb
	// Namespace
	// 剩余的资源Parts
	requestInfo.Parts = currentParts

	// parts look like: resource/resourceName/subresource/other/stuff/we/don't/interpret
	switch {
	// parts 大于3且不是specialVerbsNoSubresources (proxy)
	case len(requestInfo.Parts) >= 3 && !specialVerbsNoSubresources.Has(requestInfo.Verb):
		// 资源的子资源 /pods/foo/status, 则这里的SubResource是foo, Pod的 Status
		requestInfo.Subresource = requestInfo.Parts[2]
		fallthrough
	case len(requestInfo.Parts) >= 2:
		// 资源本身名称 /pods/foo, 则这里的Name是foo
		requestInfo.Name = requestInfo.Parts[1]
		fallthrough
	case len(requestInfo.Parts) >= 1:
		// 资源本身名称 /pods, 则这里的Resource就是 pods
		requestInfo.Resource = requestInfo.Parts[0]
	}

	// if there's no name on the request and we thought it was a get before, then the actual verb is a list or a watch
	// 请求信息中不包含resourceName并且verb 为get, 则是 list/watch请求
	if len(requestInfo.Name) == 0 && requestInfo.Verb == "get" {
		opts := metainternalversion.ListOptions{}
		// 根据URL Query 解码到ListOptions, ListOptions实际上就是
		// 我们在发送get请求是list或watch的查询信息
		if err := metainternalversionscheme.ParameterCodec.DecodeParameters(req.URL.Query(), metav1.SchemeGroupVersion, &opts); err != nil {
			// An error in parsing request will result in default to "list" and not setting "name" field.
			klog.Errorf("Couldn't parse request %#v: %v", req.URL.Query(), err)
			// Reset opts to not rely on partial results from parsing.
			// However, if watch is set, let's report it.
			opts = metainternalversion.ListOptions{}
			if values := req.URL.Query()["watch"]; len(values) > 0 {
				switch strings.ToLower(values[0]) {
				case "false", "0":
				default:
					opts.Watch = true
				}
			}
		}

		// 设置verb为list或watch
		if opts.Watch {
			requestInfo.Verb = "watch"
		} else {
			requestInfo.Verb = "list"
		}

		if opts.FieldSelector != nil {
			// 指定了匹配的资源Name
			if name, ok := opts.FieldSelector.RequiresExactMatch("metadata.name"); ok {
				if len(path.IsValidPathSegmentName(name)) == 0 {
					requestInfo.Name = name
				}
			}
		}
	}
	// if there's no name on the request and we thought it was a delete before, then the actual verb is deletecollection
	// 没有资源Name且之前的verb是delete, verb更改为deletecollection, 意味删除多个资源
	if len(requestInfo.Name) == 0 && requestInfo.Verb == "delete" {
		requestInfo.Verb = "deletecollection"
	}

	return &requestInfo, nil
}

type requestInfoKeyType int

// requestInfoKey is the RequestInfo key for the context. It's of private type here. Because
// keys are interfaces and interfaces are equal when the type and the value is equal, this
// does not conflict with the keys defined in pkg/api.
const requestInfoKey requestInfoKeyType = iota

// WithRequestInfo returns a copy of parent in which the request info value is set
func WithRequestInfo(parent context.Context, info *RequestInfo) context.Context {
	return WithValue(parent, requestInfoKey, info)
}

// RequestInfoFrom returns the value of the RequestInfo key on the ctx
func RequestInfoFrom(ctx context.Context) (*RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey).(*RequestInfo)
	return info, ok
}

// splitPath returns the segments for a URL path.
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}
