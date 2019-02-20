// +build !solaris

package analyse_log

import (
	"log"
	"strings"
	"sync"
  "regexp"
  "time"
  "strconv"
  "io/ioutil"
  "fmt"

	"github.com/influxdata/tail"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal/globpath"
	"github.com/influxdata/telegraf/plugins/inputs"
  "github.com/metakeule/fmtdate"
	//"github.com/influxdata/telegraf/plugins/parsers"
	// Parsers
)

const (
	defaultWatchMethod = "inotify"
)

type logEntry struct {
	path string
	line string
}

type analyseEntry struct {
  tags map[string]string
  count int
  sum float64
  name string
  method string
}

type fileAnalyseResult struct {
  name string
  time time.Time
  entrys map[string]*analyseEntry
}


func (ar *fileAnalyseResult) addEntry(path string, name string, tags map[string]string, value float64, method string){
  entry_key := get_parser_key(path, name, tags)

  entrys := ar.entrys
  entry, got := entrys[entry_key]

  if !got {
    new_entry := &analyseEntry {
      tags: tags,
      count: 1,
      sum: value,
      name: name,
      method: method,
    }

    entrys[entry_key] = new_entry
  } else {
    log.Printf("D! get pre entry sum: %v, count: %v", entry.sum, entry.count)
    (*entry).count = (*entry).count + 1
    (*entry).sum =  (*entry).sum + value
    log.Printf("D! get after entry sum: %v, count: %v", entry.sum, entry.count)
  }
}

func (ar *fileAnalyseResult) getResult(acc telegraf.Accumulator) {
  for _, entry_i := range (*ar).entrys {
    entry := *entry_i
    method := entry.method
    var val float64 = 0
    if entry.count > 0 {
      if method == "count" {
        val = float64(entry.count)
      } else if method == "avg" {
        val = entry.sum / float64(entry.count)
      } else if method == "sum" {
        val = float64(entry.sum)
      }
    }

    files := map[string]interface{}{entry.name: val}
    log.Printf("D! files %v, %v, %v, %v", entry.name, val, entry.tags, (*ar).time)
    acc.AddFields((*ar).name, files, entry.tags, (*ar).time)
  }
  (*ar).entrys = make(map[string]*analyseEntry)
}

func get_parser_key(path string, name string, tags map[string]string) (line_key string){
  line_key = path + ";" + name + ";"
  for key, value := range tags {
    //line_key += tag.Name
    //if tag.reg_index > 0 && tag_v := re_result[tag.reg_index] {
    line_key += key + ":" + value + ","
  }
  return
}


type tagsParser struct {
  Name string
  ValueRegIndex int
  Value string
}

type lineParser struct {
  Name string
  Value float64
  ValueRegIndex int
  ValueConditions [][]string
  Tags            []tagsParser
  AnalyseMethod string
}

// AnalyseLogPlugin is the primary struct to implement the interface for analyse_log plugin
type AnalyseLogPlugin struct {
  Files         []string
  WatchMethod   string
  Name          string

  tailers map[string]*tail.Tail
  lines   chan logEntry
  offset_info string
  // offset config
  SleepSecond int
  OffsetPositionFile string
  done    chan struct{}
  wg      sync.WaitGroup
  acc     telegraf.Accumulator
  start_flag bool

  sync.Mutex

  LineParsers []lineParser `toml:"line_parser"`
  LineMatchReg  string
  TimeRegIndex  int
  TimeFormat    string
}


const sampleConfig = `
[[inputs.analyse_log]]
   ## pre name off the metric
   name = "psr"

   ## how log set offset into file, keep same with db persistence time
   seep_second = 10
   ## default is /tmp/telegraf_tail_position.tmp
   offset_position_file = "/tmp/telegraf_tail_position.tmp"

   ## if filename has time {datetime: 'TimeFormate'}, like {datetime:YYYYMMDDhhmmss}
   files = ["/home/liuhq/go/src/github.com/influxdata/telegraf/plugins/inputs/analyse_log/dev/test.log"]

   ## line matcher
   line_match_reg = '^(.*)#(\d+)#(.*)'

   time_reg_index = 1
   # time format, help at https://github.com/metakeule/fmtdate
   time_format = "YYYYMMDDhhmmss"

   [[inputs.analyse_log.line_parser]]
     # metrice name
     name = "qps"

     ## get value by default
     ## if value_reg_index cant get, get from the default
     value = 1.0
     value_reg_index = -1

     # analyse method can be: count avg sum
     analyse_method = "count"


   [[inputs.analyse_log.line_parser]]
     name = "rt"

     ## get value by regexp
     value_reg_index = 2
     ## check value under conditions, only under value add to analyse
     value_conditions = [[">", "0"],["<", "2"]]

     # analyse method can be: count avg sum
     analyse_method = "avg"

     ## add add addtion tag
     [[inputs.analyse_log.line_parser.tags]]
        name = 'add_tags'
        value = "tag-value"
        value_reg_index = -1

     ## get tag from content line
     [[inputs.analyse_log.line_parser.tags]]
        name = 'get_tags'
        value_reg_index = 3

`

// SampleConfig returns the sample configuration for the plugin
func (l *AnalyseLogPlugin) SampleConfig() string {
	return sampleConfig
}

// Description returns the human readable description for the plugin
func (l *AnalyseLogPlugin) Description() string {
	return "Stream and parse log file(s)."
}

// Gather is the primary function to collect the metrics for the plugin
func (l *AnalyseLogPlugin) Gather(acc telegraf.Accumulator) error {
	l.Lock()
	defer l.Unlock()

	// always start from the beginning of files that appear while we're running
	return l.tailNewfiles()
}

// Start kicks off collection of stats for the plugin
func (l *AnalyseLogPlugin) Start(acc telegraf.Accumulator) error {
	l.Lock()
	defer l.Unlock()

	l.acc = acc
	l.lines = make(chan logEntry, 1000)
	l.done = make(chan struct{})
	l.tailers = make(map[string]*tail.Tail)

	l.wg.Add(1)
	go l.parser()
  go l.PersistenceOffset()

	return l.tailNewfiles()
}

// check the globs against files on disk, and start tailing any new files.
// Assumes l's lock is held!
func (l *AnalyseLogPlugin) tailNewfiles() error {
	var seeks = make(map[string]tail.SeekInfo)
  var default_seek tail.SeekInfo

  if !l.start_flag {
    offsets := l.ReadPersistenceOffset()
    for key, offset := range offsets {
      seek := tail.SeekInfo {
        Offset: offset,
        Whence: 0,
      }
      seeks[key] = seek
    }
    log.Printf("D! offset read file: %v ", seeks)
    l.start_flag = true
  }

	var poll bool
	if l.WatchMethod == "poll" {
		poll = true
	}

	// Create a "tailer" for each file
	for _, filepath := range l.Files {
    filepath = replace_path_time(filepath)
		g, err := globpath.Compile(filepath)
		if err != nil {
			log.Printf("E! Error Glob %s failed to compile, %s", filepath, err)
			continue
		}
		files := g.Match()

		for _, file := range files {
			if _, ok := l.tailers[file]; ok {
				// we're already tailing this file
				continue
			}

      file_seek, ok := seeks[file]
      if !ok {
        file_seek = default_seek
      }

			tailer, err := tail.TailFile(file,
				tail.Config{
					ReOpen:    true,
					Follow:    true,
					Location:  &file_seek,
					MustExist: true,
					Poll:      poll,
					Logger:    tail.DiscardingLogger,
				})
			if err != nil {
				l.acc.AddError(err)
				continue
			}

			log.Printf("D! [inputs.analyse_log] tail added for file: %v", file)

			// create a goroutine for each "tailer"
			l.wg.Add(1)
			go l.receiver(tailer)
			l.tailers[file] = tailer
		}
	}

	return nil
}

func replace_path_time(path string) string {
  r, _ := regexp.Compile("{datetime:(.*?)}")
  re_result := r.FindStringSubmatch(path)
  if len(re_result) > 1 {
    time_formate := re_result[1]
    date := fmtdate.Format(time_formate, time.Now())

    return strings.Replace(path, re_result[0], date, 1)
  } else {
    return path
  }
}


// receiver is launched as a goroutine to continuously watch a tailed logfile
// for changes and send any log lines down the l.lines channel.
func (l *AnalyseLogPlugin) receiver(tailer *tail.Tail) {
	defer l.wg.Done()

	var line *tail.Line
	for line = range tailer.Lines {

		if line.Err != nil {
			log.Printf("E! Error tailing file %s, Error: %s\n",
				tailer.Filename, line.Err)
			continue
		}

		// Fix up files with Windows line endings.
		text := strings.TrimRight(line.Text, "\r")

		entry := logEntry{
			path: tailer.Filename,
			line: text,
		}

		select {
		case <-l.done:
		case l.lines <- entry:
		}
	}
}

// parse is launched as a goroutine to watch the l.lines channel.
// when a line is available, parse parses it and adds the metric(s) to the
// accumulator.
func (l *AnalyseLogPlugin) parser() {
	defer l.wg.Done()

	//var m telegraf.Metric
	//var err error
	var entry logEntry

  allResults := make(map[string]*fileAnalyseResult)

	for {
		select {
		case <-l.done:
			return
		case entry = <-l.lines:
			if entry.line == "" || entry.line == "\n" {
				continue
			}
		}

    r, _ := regexp.Compile(l.LineMatchReg)
    re_result := r.FindStringSubmatch(entry.line)
    re_len := len(re_result)

    if re_result == nil || re_len <= 1 || re_len < l.TimeRegIndex {
      log.Printf("D! regexp: %v not match", l.LineMatchReg)
      continue
    }
    path := entry.path

    line_time_str := re_result[l.TimeRegIndex]
    t, err := fmtdate.Parse(l.TimeFormat, line_time_str)
    if err != nil {
      log.Printf("E! Error formate time %s err %s", line_time_str, err)
    }

    fileResult, ok := allResults[path]
    if !ok {
      fileResult = &fileAnalyseResult {
        name: l.Name,
        time: t,
        entrys: make(map[string]*analyseEntry),
      }
      allResults[path] = fileResult
    }


    if (*fileResult).time.Unix() != t.Unix() {
      fileResult.getResult(l.acc)
      (*fileResult).time = t
    }

    for _, lp := range l.LineParsers {
      value, tags := get_line_value(lp, re_result)

      if checkSkipByCondition(lp.ValueConditions, value) {
        log.Printf("D! line value: %v, skip by value conditions", value)
        continue
      }

      fileResult.addEntry(path, lp.Name, tags, value, lp.AnalyseMethod)
    }
	}
}

func get_line_value(lp lineParser, re_result []string) (value float64, tags map[string]string) {
  re_len := len(re_result)
  value = 0

  if lp.ValueRegIndex > 1 && lp.ValueRegIndex <= re_len {
    value_str := re_result[lp.ValueRegIndex]
    val, err := strconv.ParseFloat(value_str, 64)
    if err == nil {
      value = val
    } else {
      log.Printf("E! line value Parse Float error: %v", err)
    }
  }

  tags = make(map[string]string)
  for _, tag_c := range lp.Tags {
    if tag_c.Value != "" {
      tags[tag_c.Name] = tag_c.Value
    } else if tag_c.ValueRegIndex > 0 && tag_c.ValueRegIndex <= re_len {
      tags[tag_c.Name] = re_result[tag_c.ValueRegIndex]
    }
  }
  return
}

func checkSkipByCondition(conditions [][]string, value float64) bool{
  if conditions == nil  {
    return false
  }

  under_flag := true
  for _, condt := range conditions {
    cond_t, cond_v := condt[0], condt[1]
    val, err := strconv.ParseFloat(cond_v, 64)
    if err != nil {
      log.Printf("!D condition value err : %v", val)
      return true
    }
    if cond_t == ">" {
      under_flag = value > val
    } else if cond_t == "<" {
      under_flag = value < val
    } else if cond_t == "==" {
      under_flag = value == val
    }

    if !under_flag {
      return true
    }
  }

  return false
}


func (l *AnalyseLogPlugin) PersistenceOffset() {
  for {
    time.Sleep(time.Duration(l.SleepSecond) * time.Second)

    offset_info := ""

    for _, tailer := range l.tailers {
      offset, err := tailer.Tell()

      if err == nil {
        offset_info += fmt.Sprintf("%s=%d,", tailer.Filename, offset)
      }
    }

    off_byte := []byte(offset_info)
    position_file := l.OffsetPositionFile
    if position_file == "" {
      position_file = "/tmp/telegraf_tail_position.tmp"
    }
    err := ioutil.WriteFile("/tmp/telegraf_tail_position.tmp", off_byte, 0644)
    if err != nil {
      log.Printf("E! write offset to file error: %v", err)
    }

    l.offset_info = offset_info
  }
}

func (l *AnalyseLogPlugin) ReadPersistenceOffset() map[string]int64{
  offset_info := map[string]int64{}

  position_file := l.OffsetPositionFile
  if position_file == "" {
    position_file = "/tmp/telegraf_tail_position.tmp"
  }
  info_b, err := ioutil.ReadFile(position_file)
  if err != nil {
    log.Printf("D! read offset error: %v", err)
    return offset_info
  }
  info_str := string(info_b)

  info_arr := strings.Split(info_str, ",")
  for _, inf := range info_arr {
    inf_a := strings.Split(inf, "=")
    if len(inf_a) == 2 {
      offset, err := strconv.ParseInt(inf_a[1], 10, 64)
      if err != nil {
        continue
      }
      offset_info[inf_a[0]] = offset
    }
  }
  return offset_info
}

// Stop will end the metrics collection process on file tailers
func (l *AnalyseLogPlugin) Stop() {
	l.Lock()
	defer l.Unlock()

	for _, t := range l.tailers {
		err := t.Stop()

		//message for a stopped tailer
		log.Printf("D! tail dropped for file: %v", t.Filename)

		if err != nil {
			log.Printf("E! Error stopping tail on file %s\n", t.Filename)
		}
		t.Cleanup()
	}
	close(l.done)
	l.wg.Wait()
}

func init() {
	inputs.Add("analyse_log", func() telegraf.Input {
		return &AnalyseLogPlugin{
			WatchMethod: defaultWatchMethod,
		}
	})
}
