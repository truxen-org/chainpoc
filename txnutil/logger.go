package txnutil

import (
	"fmt"
	"log"
	"os"
	"path"
)

type LogType byte

const (
	LogTypeStdIn = 1
	LogTypeFile  = 2
)

var Log *Logger

func InitLogger() {
	if Config == nil {
		log.Fatal("config.json missing.")
	}
	base := path.Join(Config.BaseDir, ".chainpoc")
	d := Config.Debug
	// usr, _ := user.Current()
	// bpath := path.Join(usr.HomeDir, base)
	bpath := base
	if len(base) > 0 {
		//Check if the logging directory already exists, create it if not
		_, err := os.Stat(bpath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("Debug logging directory %s doesn't exist, creating it\n", bpath)
				os.Mkdir(bpath, 0777)
			}
		}
	}

	level := LogLevelInfo
	if d {
		level = LogLevelDebug
	}
	Log = NewLogger(LogFile|LogStd, level, bpath)
}

type LoggerType byte

const (
	LogFile = 0x1
	LogStd  = 0x2
)

type LogSystem interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

type Logger struct {
	logSys   []LogSystem
	logLevel int
}

func NewLogger(flag LoggerType, level int, bpath string) *Logger {
	var loggers []LogSystem

	flags := log.LstdFlags

	if flag&LogFile > 0 {
		file, err := os.OpenFile(path.Join(bpath, "debug.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
		if err != nil {
			log.Panic("unable to create file: ", err)
		}

		log := log.New(file, "", flags)

		loggers = append(loggers, log)
	}
	if flag&LogStd > 0 {
		log := log.New(os.Stdout, "", flags)
		loggers = append(loggers, log)
	}

	return &Logger{logSys: loggers, logLevel: level}
}

func (log *Logger) AddLogSystem(logger LogSystem) {
	log.logSys = append(log.logSys, logger)
}

const (
	LogLevelDebug = iota
	LogLevelInfo
)

func (log *Logger) Debugln(v ...interface{}) {
	if log.logLevel != LogLevelDebug {
		return
	}

	for _, logger := range log.logSys {
		logger.Println(v...)
	}
}

func (log *Logger) Debugf(format string, v ...interface{}) {
	if log.logLevel != LogLevelDebug {
		return
	}

	for _, logger := range log.logSys {
		logger.Printf(format, v...)
	}
}

func (log *Logger) Infoln(v ...interface{}) {
	if log.logLevel > LogLevelInfo {
		return
	}

	fmt.Println(len(log.logSys))
	for _, logger := range log.logSys {
		logger.Println(v...)
	}
}

func (log *Logger) Infof(format string, v ...interface{}) {
	if log.logLevel > LogLevelInfo {
		return
	}

	for _, logger := range log.logSys {
		logger.Printf(format, v...)
	}
}
