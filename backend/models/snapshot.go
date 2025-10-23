package models

type Snapshot struct {
	ID         int
	ReceivedAt string
	ClusterID  string
	Kind       string
	Payload    string
}
