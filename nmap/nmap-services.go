package gonmap

// Service 代表一个服务条目
type Service struct {
	Name        string  `json:"name"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol"`
	Probability float64 `json:"probability"`
	Comments    string  `json:"comments,omitempty"`
}

// ServicesData 代表解析后的services数据结构
type ServicesData struct {
	Services []Service `json:"services"`
}
