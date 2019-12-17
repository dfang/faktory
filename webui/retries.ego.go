// Generated by ego.
// DO NOT EDIT

//line retries.ego:1

package webui

import "fmt"
import "html"
import "io"
import "context"

import (
	"net/http"

	"github.com/contribsys/faktory/client"
	"github.com/contribsys/faktory/storage"
)

func ego_listRetries(w io.Writer, req *http.Request, set storage.SortedSet, count, currentPage uint64) {
	totalSize := uint64(set.Size())

//line retries.ego:14
	_, _ = io.WriteString(w, "\n\n")
//line retries.ego:15
	ego_layout(w, req, func() {
//line retries.ego:16
		_, _ = io.WriteString(w, "\n\n\n<header class=\"row\">\n  <div class=\"col-sm-5\">\n    <h3>")
//line retries.ego:20
		_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Retries"))))
//line retries.ego:20
		_, _ = io.WriteString(w, "</h3>\n  </div>\n  ")
//line retries.ego:22
		if totalSize > count {
//line retries.ego:23
			_, _ = io.WriteString(w, "\n    <div class=\"col-sm-7\">\n      ")
//line retries.ego:24
			ego_paging(w, req, "/retries", totalSize, count, currentPage)
//line retries.ego:25
			_, _ = io.WriteString(w, "\n    </div>\n  ")
//line retries.ego:26
		}
//line retries.ego:27
		_, _ = io.WriteString(w, "\n  ")
//line retries.ego:27
		_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(filtering("retries"))))
//line retries.ego:28
		_, _ = io.WriteString(w, "\n</header>\n\n")
//line retries.ego:30
		if totalSize > 0 {
//line retries.ego:31
			_, _ = io.WriteString(w, "\n  <form action=\"")
//line retries.ego:31
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(relative(req, "/retries"))))
//line retries.ego:31
			_, _ = io.WriteString(w, "\" method=\"post\">\n    ")
//line retries.ego:32
			_, _ = fmt.Fprint(w, csrfTag(req))
//line retries.ego:33
			_, _ = io.WriteString(w, "\n    <div class=\"table_container\">\n      <table class=\"table table-striped table-bordered table-white\">\n        <thead>\n          <tr>\n            <th class=\"table-checkbox checkbox-column\">\n              <label>\n                <input type=\"checkbox\" class=\"check_all\" />\n              </label>\n            </th>\n            <th>")
//line retries.ego:42
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "NextRetry"))))
//line retries.ego:42
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line retries.ego:43
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "RetryCount"))))
//line retries.ego:43
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line retries.ego:44
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Queue"))))
//line retries.ego:44
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line retries.ego:45
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Job"))))
//line retries.ego:45
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line retries.ego:46
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Arguments"))))
//line retries.ego:46
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line retries.ego:47
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Error"))))
//line retries.ego:47
			_, _ = io.WriteString(w, "</th>\n          </tr>\n        </thead>\n        ")
//line retries.ego:50
			setJobs(set, count, currentPage, func(idx int, key []byte, job *client.Job) {
//line retries.ego:51
				_, _ = io.WriteString(w, "\n          <tr>\n            <td class=\"table-checkbox\">\n              <label>\n                <input type='checkbox' name='key' value='")
//line retries.ego:54
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(string(key))))
//line retries.ego:54
				_, _ = io.WriteString(w, "' />\n              </label>\n            </td>\n            <td>\n              <a href=\"")
//line retries.ego:58
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(root(req))))
//line retries.ego:58
				_, _ = io.WriteString(w, "/retries/")
//line retries.ego:58
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(string(key))))
//line retries.ego:58
				_, _ = io.WriteString(w, "\">")
//line retries.ego:58
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(relativeTime(job.Failure.NextAt))))
//line retries.ego:58
				_, _ = io.WriteString(w, "</a>\n            </td>\n            <td>")
//line retries.ego:60
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Failure.RetryCount)))
//line retries.ego:60
				_, _ = io.WriteString(w, "</td>\n            <td>\n              <a href=\"")
//line retries.ego:62
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(root(req))))
//line retries.ego:62
				_, _ = io.WriteString(w, "/queues/")
//line retries.ego:62
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Queue)))
//line retries.ego:62
				_, _ = io.WriteString(w, "\">")
//line retries.ego:62
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Queue)))
//line retries.ego:62
				_, _ = io.WriteString(w, "</a>\n            </td>\n            <td><code>")
//line retries.ego:64
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Type)))
//line retries.ego:64
				_, _ = io.WriteString(w, "</code></td>\n            <td>\n              <div class=\"args\">")
//line retries.ego:66
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(displayArgs(job.Args))))
//line retries.ego:66
				_, _ = io.WriteString(w, "</div>\n            </td>\n            <td>\n              <div>")
//line retries.ego:69
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Failure.ErrorType)))
//line retries.ego:69
				_, _ = io.WriteString(w, ": ")
//line retries.ego:69
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(job.Failure.ErrorMessage)))
//line retries.ego:69
				_, _ = io.WriteString(w, "</div>\n            </td>\n          </tr>\n        ")
//line retries.ego:72
			})
//line retries.ego:73
			_, _ = io.WriteString(w, "\n      </table>\n    </div>\n    <div class=\"pull-left flip\">\n      <button class=\"btn btn-primary btn-sm\" type=\"submit\" name=\"action\" value=\"retry\">")
//line retries.ego:76
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "RetryNow"))))
//line retries.ego:76
			_, _ = io.WriteString(w, "</button>\n      <button class=\"btn btn-warn btn-sm\" type=\"submit\" name=\"action\" value=\"delete\">")
//line retries.ego:77
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Delete"))))
//line retries.ego:77
			_, _ = io.WriteString(w, "</button>\n      <button class=\"btn btn-danger btn-sm\" type=\"submit\" name=\"action\" value=\"kill\">")
//line retries.ego:78
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Kill"))))
//line retries.ego:78
			_, _ = io.WriteString(w, "</button>\n    </div>\n  </form>\n\n  ")
//line retries.ego:82
			if unfiltered() {
//line retries.ego:83
				_, _ = io.WriteString(w, "\n    <form action=\"")
//line retries.ego:83
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(relative(req, "/retries"))))
//line retries.ego:83
				_, _ = io.WriteString(w, "\" method=\"post\">\n      ")
//line retries.ego:84
				_, _ = fmt.Fprint(w, csrfTag(req))
//line retries.ego:85
				_, _ = io.WriteString(w, "\n      <input type=\"hidden\" name=\"key\" value=\"all\" />\n      <div class=\"pull-right flip\">\n        <button class=\"btn btn-primary btn-sm\" type=\"submit\" name=\"action\" value=\"retry\" data-confirm=\"")
//line retries.ego:87
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "AreYouSure"))))
//line retries.ego:87
				_, _ = io.WriteString(w, "\">")
//line retries.ego:87
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "RetryAll"))))
//line retries.ego:87
				_, _ = io.WriteString(w, "</button>\n        <button class=\"btn btn-danger btn-sm\" type=\"submit\" name=\"action\" value=\"delete\" data-confirm=\"")
//line retries.ego:88
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "AreYouSure"))))
//line retries.ego:88
				_, _ = io.WriteString(w, "\">")
//line retries.ego:88
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "DeleteAll"))))
//line retries.ego:88
				_, _ = io.WriteString(w, "</button>\n      </div>\n    </form>\n  ")
//line retries.ego:91
			}
//line retries.ego:92
			_, _ = io.WriteString(w, "\n\n")
//line retries.ego:93
		} else {
//line retries.ego:94
			_, _ = io.WriteString(w, "\n  <div class=\"alert alert-success\">")
//line retries.ego:94
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "NoRetriesFound"))))
//line retries.ego:94
			_, _ = io.WriteString(w, "</div>\n")
//line retries.ego:95
		}
//line retries.ego:96
		_, _ = io.WriteString(w, "\n")
//line retries.ego:96
	})
//line retries.ego:97
	_, _ = io.WriteString(w, "\n")
//line retries.ego:97
}

var _ fmt.Stringer
var _ io.Reader
var _ context.Context
var _ = html.EscapeString
