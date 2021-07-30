package runner

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/collaborator"
	"github.com/projectdiscovery/collaborator/pkg/types"
	"github.com/projectdiscovery/gologger"
)

// Runner contains the internal logic of the program
type Runner struct {
	options    *types.Options
	burpcollab *collaborator.BurpCollaborator
}

// NewRunner instance
func NewRunner(options *types.Options) (*Runner, error) {
	burpcollab := collaborator.NewBurpCollaborator()

	return &Runner{options: options, burpcollab: burpcollab}, nil
}

// Run collab polling
func (r *Runner) Run() error {

	// If BIID not passed via cli
	if r.options.BIID == "" {
		return fmt.Errorf("BIID not specified or not found")
	}

	gologger.Print().Msgf("Using BIID: %s", r.options.BIID)
	r.burpcollab.AddBIID(r.options.BIID)

	err := r.burpcollab.Poll()
	if err != nil {
		return err
	}

	pollTime := time.Duration(r.options.Interval) * time.Second
	for {
		time.Sleep(pollTime)
		//nolint:errcheck
		r.burpcollab.Poll()

		for _, httpresp := range r.burpcollab.RespBuffer {
			for i := range httpresp.Responses {
				resp := httpresp.Responses[i]
				var at int64
				var msg string
				at, _ = strconv.ParseInt(resp.Time, 10, 64)
				atTime := time.Unix(0, at*int64(time.Millisecond))
				switch resp.Protocol {
				case "http", "https":

					rr := strings.NewReplacer(
						"{{protocol}}", strings.ToUpper(resp.Protocol),
						"{{from}}", resp.Client,
						"{{time}}", atTime.String(),
						"{{request}}", resp.Data.RequestDecoded,
						"{{response}}", resp.Data.ResponseDecoded,
					)
					msg = rr.Replace(r.options.HTTPMessage)

				case "dns":
					rr := strings.NewReplacer(
						"{{type}}", resp.Data.RequestType,
						"{{domain}} ", resp.Data.SubDomain,
						"{{from}}", resp.Client,
						"{{time}}", atTime.String(),
						"{{request}}", resp.Data.RawRequestDecoded,
					)
					msg = rr.Replace(r.options.DNSMessage)

				case "smtp":
					rr := strings.NewReplacer(
						"{{from}}", resp.Client,
						"{{time}}", atTime.String(),
						"{{sender}}", resp.Data.SenderDecoded,
						"{{recipients}}", strings.Join(resp.Data.RecipientsDecoded, ","),
						"{{message}}", resp.Data.MessageDecoded,
						"{{conversation}}", resp.Data.ConversationDecoded,
					)
					msg = rr.Replace(r.options.SMTPMessage)
				}
				gologger.Print().Msgf(msg)
			}
		}
		r.burpcollab.Empty()
	}
}

// Close the runner instance
func (r *Runner) Close() {
	r.burpcollab.Empty()
}
