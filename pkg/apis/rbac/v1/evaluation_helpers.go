/*
Copyright 2018 The Kubernetes Authors.

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

package v1

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func RoleRefGroupKind(roleRef rbacv1.RoleRef) schema.GroupKind {
	return schema.GroupKind{Group: roleRef.APIGroup, Kind: roleRef.Kind}
}

func VerbMatches(rule *rbacv1.PolicyRule, requestedVerb string) bool {
	for _, ruleVerb := range rule.Verbs {
		if ruleVerb == rbacv1.VerbAll {
			return true
		}
		if ruleVerb == requestedVerb {
			return true
		}
	}

	return false
}

func APIGroupMatches(rule *rbacv1.PolicyRule, requestedGroup string) bool {
	for _, ruleGroup := range rule.APIGroups {
		if ruleGroup == rbacv1.APIGroupAll {
			return true
		}
		if ruleGroup == requestedGroup {
			return true
		}
	}

	return false
}

func ResourceMatches(rule *rbacv1.PolicyRule, combinedRequestedResource, requestedSubresource string) bool {
	for _, ruleResource := range rule.Resources {
		// if everything is allowed, we match
		// resource为 * 返回true, 结束匹配
		if ruleResource == rbacv1.ResourceAll {
			return true
		}
		// if we have an exact match, we match
		// 资源完全匹配（包括资源和子资源）
		if ruleResource == combinedRequestedResource {
			return true
		}

		// We can also match a */subresource.
		// if there isn't a subresource, then continue
		// 请求中不包含子资源结束匹配
		if len(requestedSubresource) == 0 {
			continue
		}
		// if the rule isn't in the format */subresource, then we don't match, continue
		// 子资源匹配算法, kubernetes在rule的resources定义中, 包含子资源的格式为 */subresource,
		if len(ruleResource) == len(requestedSubresource)+2 &&
			strings.HasPrefix(ruleResource, "*/") &&
			strings.HasSuffix(ruleResource, requestedSubresource) {
			return true

		}
	}

	return false
}

// ResourceNameMatches 按照rule引用的resourceNames做匹配, 不过需要注意对某些action或operation,
// 例如 create 和 deletecollection 的请求, 不能通过resourceName做限制, 因为对象name在授权时可能是未知的
func ResourceNameMatches(rule *rbacv1.PolicyRule, requestedName string) bool {
	// rule 为定义resourceNames, 返回true, 匹配结束
	if len(rule.ResourceNames) == 0 {
		return true
	}

	// 遍历rule定义的所有的resourceName进行匹配
	for _, ruleName := range rule.ResourceNames {
		// 短路逻辑, 如果resourceNames集合有一个和请求的资源名称匹配, 则返回true
		if ruleName == requestedName {
			return true
		}
	}

	return false
}

// NonResourceURLMatches 执行非资源请求的URL路径匹配算法
func NonResourceURLMatches(rule *rbacv1.PolicyRule, requestedURL string) bool {
	for _, ruleURL := range rule.NonResourceURLs {
		// ruleURL 为 *, 表示允许所有非资源的请求, 返回true, 匹配结束
		if ruleURL == rbacv1.NonResourceAll {
			return true
		}
		// ruleURL 和 requestedURL 完全匹配, 例如 ruleURL = /logs/*, requestURL = /logs/*
		if ruleURL == requestedURL {
			return true
		}

		// 1. ruleURL 包含后缀 *, 例如 /logs/*
		// 2. 去除ruleURL的后缀 *, 例如 /logs/* -> /logs/ 判断去除后缀后的ruleURL是
		//	  否包含 requestURL前缀, 例如 requestURL = /logs, ruleURL = /logs/, 则是包含的
		// 上述两个条件全部满足返回true, 结束匹配
		if strings.HasSuffix(ruleURL, "*") && strings.HasPrefix(requestedURL, strings.TrimRight(ruleURL, "*")) {
			return true
		}
	}

	return false
}

// subjectsStrings returns users, groups, serviceaccounts, unknown for display purposes.
func SubjectsStrings(subjects []rbacv1.Subject) ([]string, []string, []string, []string) {
	users := []string{}
	groups := []string{}
	sas := []string{}
	others := []string{}

	for _, subject := range subjects {
		switch subject.Kind {
		case rbacv1.ServiceAccountKind:
			sas = append(sas, fmt.Sprintf("%s/%s", subject.Namespace, subject.Name))

		case rbacv1.UserKind:
			users = append(users, subject.Name)

		case rbacv1.GroupKind:
			groups = append(groups, subject.Name)

		default:
			others = append(others, fmt.Sprintf("%s/%s/%s", subject.Kind, subject.Namespace, subject.Name))
		}
	}

	return users, groups, sas, others
}

func String(r rbacv1.PolicyRule) string {
	return "PolicyRule" + CompactString(r)
}

// CompactString exposes a compact string representation for use in escalation error messages
func CompactString(r rbacv1.PolicyRule) string {
	formatStringParts := []string{}
	formatArgs := []interface{}{}
	if len(r.APIGroups) > 0 {
		formatStringParts = append(formatStringParts, "APIGroups:%q")
		formatArgs = append(formatArgs, r.APIGroups)
	}
	if len(r.Resources) > 0 {
		formatStringParts = append(formatStringParts, "Resources:%q")
		formatArgs = append(formatArgs, r.Resources)
	}
	if len(r.NonResourceURLs) > 0 {
		formatStringParts = append(formatStringParts, "NonResourceURLs:%q")
		formatArgs = append(formatArgs, r.NonResourceURLs)
	}
	if len(r.ResourceNames) > 0 {
		formatStringParts = append(formatStringParts, "ResourceNames:%q")
		formatArgs = append(formatArgs, r.ResourceNames)
	}
	if len(r.Verbs) > 0 {
		formatStringParts = append(formatStringParts, "Verbs:%q")
		formatArgs = append(formatArgs, r.Verbs)
	}
	formatString := "{" + strings.Join(formatStringParts, ", ") + "}"
	return fmt.Sprintf(formatString, formatArgs...)
}

type SortableRuleSlice []rbacv1.PolicyRule

func (s SortableRuleSlice) Len() int      { return len(s) }
func (s SortableRuleSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SortableRuleSlice) Less(i, j int) bool {
	return strings.Compare(s[i].String(), s[j].String()) < 0
}
