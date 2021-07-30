package types

type Options struct {
	BIID string `yaml:"burp_biid,omitempty"`

	Verbose  bool `yaml:"verbose,omitempty"`
	Silent   bool `yaml:"silent,omitempty"`
	Version  bool `yaml:"version,omitempty"`
	Interval int  `yaml:"interval,omitempty"`

	HTTPMessage string `yaml:"http_message,omitempty"`
	DNSMessage  string `yaml:"dns_message,omitempty"`
	CLIMessage  string `yaml:"cli_message,omitempty"`
	SMTPMessage string `yaml:"smtp_message,omitempty"`
}
