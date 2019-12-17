// Generated by ego.
// DO NOT EDIT

//line cron.ego:1

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

func ego_listCron(w io.Writer, req *http.Request, set storage.SortedSet, count, currentPage uint64) {
	totalSize := uint64(set.Size())

//line cron.ego:14
	_, _ = io.WriteString(w, "\n\n")
//line cron.ego:15
	ego_layout(w, req, func() {
//line cron.ego:16
		_, _ = io.WriteString(w, "\n\n<header class=\"row\">\n  <div class=\"col-sm-5\">\n    <h3>")
//line cron.ego:19
		_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Cron Jobs"))))
//line cron.ego:19
		_, _ = io.WriteString(w, "</h3>\n  </div>\n</header>\n\n")
//line cron.ego:23
		if totalSize > 0 {
//line cron.ego:24
			_, _ = io.WriteString(w, "\n    ")
//line cron.ego:24
			_, _ = fmt.Fprint(w, csrfTag(req))
//line cron.ego:25
			_, _ = io.WriteString(w, "\n    <div class=\"table_container\">\n      <table class=\"table table-striped table-bordered table-white\">\n        <thead>\n          <tr>\n            <th>")
//line cron.ego:29
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "When"))))
//line cron.ego:29
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line cron.ego:30
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Queue"))))
//line cron.ego:30
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line cron.ego:31
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Job"))))
//line cron.ego:31
			_, _ = io.WriteString(w, "</th>\n            <th>")
//line cron.ego:32
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "Arguments"))))
//line cron.ego:32
			_, _ = io.WriteString(w, "</th>\n          </tr>\n        </thead>\n        ")
//line cron.ego:35
			cronJobs(set, count, currentPage, func(idx int, cron *client.Cron) {
//line cron.ego:36
				_, _ = io.WriteString(w, "\n          <tr>\n            <td>\n               <code>")
//line cron.ego:38
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(cron.Schedule)))
//line cron.ego:38
				_, _ = io.WriteString(w, "</code>\n            </td>\n            <td>\n              <a href=\"/queues/")
//line cron.ego:41
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(cron.Job.Queue)))
//line cron.ego:41
				_, _ = io.WriteString(w, "\">")
//line cron.ego:41
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(cron.Job.Queue)))
//line cron.ego:41
				_, _ = io.WriteString(w, "</a>\n            </td>\n            <td><code>")
//line cron.ego:43
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(cron.Job.Type)))
//line cron.ego:43
				_, _ = io.WriteString(w, "</code></td>\n            <td>\n               <div class=\"args\">")
//line cron.ego:45
				_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(displayArgs(cron.Job.Args))))
//line cron.ego:45
				_, _ = io.WriteString(w, "</div>\n            </td>\n          </tr>\n        ")
//line cron.ego:48
			})
//line cron.ego:49
			_, _ = io.WriteString(w, "\n      </table>\n    </div>\n")
//line cron.ego:51
		} else {
//line cron.ego:52
			_, _ = io.WriteString(w, "\n  <div class=\"alert alert-success\">")
//line cron.ego:52
			_, _ = io.WriteString(w, html.EscapeString(fmt.Sprint(t(req, "NoCronFound"))))
//line cron.ego:52
			_, _ = io.WriteString(w, "</div>\n")
//line cron.ego:53
		}
//line cron.ego:54
		_, _ = io.WriteString(w, "\n")
//line cron.ego:54
	})
//line cron.ego:55
	_, _ = io.WriteString(w, "\n")
//line cron.ego:55
}

var _ fmt.Stringer
var _ io.Reader
var _ context.Context
var _ = html.EscapeString
