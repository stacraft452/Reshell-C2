package iplocation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Location IP地理位置信息
type Location struct {
	Country  string `json:"country"`
	Region   string `json:"region"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	Timezone string `json:"timezone"`
}

// Locator IP地理位置查询器
type Locator struct {
	client *http.Client
}

// NewLocator 创建IP地理位置查询器
func NewLocator() *Locator {
	return &Locator{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Query 查询IP地理位置（使用免费的IP-API服务）
func (l *Locator) Query(ip string) (*Location, error) {
	if ip == "" || ip == "unknown" || ip == "127.0.0.1" {
		return &Location{
			Country: "Local",
			Region:  "Local",
			City:    "Local",
			ISP:     "Local",
		}, nil
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip)
	
	resp, err := l.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("query ip location failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Timezone    string `json:"timezone"`
		Query       string `json:"query"`
		Message     string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response failed: %w", err)
	}

	if result.Status != "success" {
		return &Location{
			Country: "Unknown",
			Region:  "Unknown",
			City:    "Unknown",
			ISP:     "Unknown",
		}, nil
	}

	return &Location{
		Country:  result.Country,
		Region:   result.RegionName,
		City:     result.City,
		ISP:      result.ISP,
		Timezone: result.Timezone,
	}, nil
}

// QueryBatch 批量查询IP地理位置
func (l *Locator) QueryBatch(ips []string) map[string]*Location {
	results := make(map[string]*Location)
	for _, ip := range ips {
		loc, err := l.Query(ip)
		if err != nil {
			results[ip] = &Location{
				Country: "Unknown",
				Region:  "Unknown",
				City:    "Unknown",
				ISP:     "Unknown",
			}
		} else {
			results[ip] = loc
		}
		// 免费API有速率限制，每分钟45次
		time.Sleep(100 * time.Millisecond)
	}
	return results
}

// FormatLocation 格式化地理位置显示
func FormatLocation(loc *Location) string {
	if loc == nil {
		return "Unknown"
	}
	if loc.Country == "Local" {
		return "本地"
	}
	if loc.Country == "Unknown" {
		return "未知"
	}
	return fmt.Sprintf("%s %s", loc.Country, loc.Region)
}
