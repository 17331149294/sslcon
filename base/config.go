package base

var (
	Cfg            = &ClientConfig{}
	LocalInterface = &Interface{}
)

type ClientConfig struct {
	LogLevel           string `json:"log_level"`
	LogPath            string `json:"log_path"`
	InsecureSkipVerify bool   `json:"skip_verify"`
	CiscoCompat        bool   `json:"cisco_compat"`
	NoDTLS             bool   `json:"no_dtls"`
	AgentName          string `json:"agent_name"`
	AgentVersion       string `json:"agent_version"`
}

// Interface 应该由外部接口设置
type Interface struct {
	Name     string `json:"name"`
	Ip4      string `json:"ip4"`
	Mac      string `json:"mac"`
	Gateway  string `json:"gateway"`
	Gateway6 string `json:"gateway6"` // 物理网卡的 IPv6 网关，服务器为 IPv6 时添加路由用
}

func initCfg() {
	Cfg.LogLevel = "Debug"
	Cfg.InsecureSkipVerify = true
	Cfg.CiscoCompat = true
	Cfg.AgentName = ""
	Cfg.AgentVersion = "4.10.07062"
}
