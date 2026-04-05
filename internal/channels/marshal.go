package channels

import (
	"fmt"
	"strconv"

	"c2/internal/jsonutil"
)

// MarshalCommandLine 与 Agent 的 C++ 扁平 JSON 解析一致：扁平 type/id/参数，数字等转为字符串。
func MarshalCommandLine(cmdType, cmdID string, payload map[string]interface{}) ([]byte, error) {
	flat := map[string]interface{}{
		"type": cmdType,
		"id":   cmdID,
	}
	for k, v := range payload {
		flat[k] = normalizeJSONValue(v)
	}
	return jsonutil.MarshalCompact(flat)
}

func normalizeJSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", val)
	}
}
