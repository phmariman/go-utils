package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// from /usr/include/sys/syslog.h
	LOG_EMERG int = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERROR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

type Record struct {
	Timestamp string `json:"timestamp"`
	Priority  string `json:"priority"`
	Host      string `json:"host"`
	User      string `json:"user"`
	Process   string `json:"process"`
	Pid       string `json:"pid"`
	Message   string `json:"message"`
}

var (
	process  string
	hostname string
	username string
	pid      string
	loglevel int
	ErrInval error = errors.New("invalid argument")
)

func init() {
	var err error

	process = path.Base(os.Args[0])
	pid = strconv.FormatInt(int64(os.Getpid()), 10)

	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	userdata, err := user.Current()
	if err != nil {
		username = "unknown"
	} else {
		username = userdata.Username
	}

	// set default loglevel to LOG_WARNING
	loglevel = LOG_WARNING
}

func SetLogLevel(priority int) error {
	if priority < LOG_EMERG || priority > LOG_DEBUG {
		return ErrInval
	} else {
		loglevel = priority
		return nil
	}
}

func priorityEnabled(priority int) (bool, error) {
	if priority < LOG_EMERG || priority > LOG_DEBUG {
		return false, ErrInval
	}

	if priority <= loglevel {
		return true, nil
	} else {
		return false, nil
	}
}

func getPriorityStr(priority int) (string, error) {
	switch priority {
	case LOG_EMERG:
		return "EMERGENCY", nil
	case LOG_ALERT:
		return "ALERT", nil
	case LOG_CRIT:
		return "CRITICAL", nil
	case LOG_ERROR:
		return "ERROR", nil
	case LOG_WARNING:
		return "WARNING", nil
	case LOG_NOTICE:
		return "NOTICE", nil
	case LOG_INFO:
		return "INFO", nil
	case LOG_DEBUG:
		return "DEBUG", nil
	default:
		return "", ErrInval
	}
}

func printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func Logf(priority int, format string, args ...interface{}) error {
	if ok, err := priorityEnabled(priority); ok == false {
		return err
	}

	pstr, err := getPriorityStr(priority)
	if err != nil {
		return err
	}

	format = strings.TrimSuffix(format, "\n")

	printf("[%s] ", time.Now().Local().Format("2006-01-02 15:04:05.000"))
	printf("[%s:%s] ", process, pid)
	printf("[%s] ", pstr)
	printf(format, args...)
	printf("\n")

	return nil
}

func LogRecord(priority int, format string, args ...interface{}) error {
	priostr, err := getPriorityStr(priority)
	if err != nil {
		return err
	}

	format = strings.TrimSuffix(format, "\n")

	record := Record{time.Now().Local().Format("2006-01-02 15:04:05.000"), priostr,
		hostname, username, process, pid, fmt.Sprintf(format, args)}

	jrecord, _ := json.Marshal(record)
	fmt.Println(string(jrecord))

	return nil
}

func LogRecordPretty(priority int, format string, args ...interface{}) error {
	priostr, err := getPriorityStr(priority)
	if err != nil {
		return err
	}

	format = strings.TrimSuffix(format, "\n")

	record := Record{time.Now().Local().Format("2006-01-02 15:04:05.000"), priostr,
		hostname, username, process, pid, fmt.Sprintf(format, args)}

	jrecord, _ := json.MarshalIndent(record, "", "    ")
	fmt.Println(string(jrecord))

	return nil
}
