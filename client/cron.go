package client

import "encoding/json"

type Cron struct {
	Schedule string `json:"schedule"`
	Job      Job    `json:"job"`
}

func (m *Cron) UnmarshalBinary(data []byte) error {
	// convert data to yours, let's assume its json data
	return json.Unmarshal(data, m)
}

func (m *Cron) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}
