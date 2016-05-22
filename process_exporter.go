package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/procfs"
)

// https://github.com/prometheus/procfs/blob/master/proc_stat.go
//
// Originally, this USER_HZ value was dynamically retrieved via a sysconf call
// which required cgo. However, that caused a lot of problems regarding
// cross-compilation. Alternatives such as running a binary to determine the
// value, or trying to derive it in some other way were all problematic.  After
// much research it was determined that USER_HZ is actually hardcoded to 100 on
// all Go-supported platforms as of the time of this writing. This is why we
// decided to hardcode it here as well. It is not impossible that there could
// be systems with exceptions, but they should be very exotic edge cases, and
// in that case, the worst outcome will be two misreported metrics.
//
// See also the following discussions:
//
// - https://github.com/prometheus/node_exporter/issues/52
// - https://github.com/prometheus/procfs/pull/2
// - http://stackoverflow.com/questions/17410841/how-does-user-hz-solve-the-jiffy-scaling-issue
const userHZ = 100

var version string

var (
	addr       = flag.String("listen-address", ":9011", "The address to listen on for HTTP requests.")
	userOpt    = flag.String("user", "", "User")
	filter     = flag.String("filter", "", "Commandline filter")
	procfsPath = flag.String("procfs", procfs.DefaultMountPoint, "procfs path")
	versionFlg = flag.Bool("version", false, "Show version number")
)

const namespace = "proc"

type Exporter struct {
	mutex sync.RWMutex

	uid         *uint32
	filterRegex *regexp.Regexp

	bootTime float64
	pagesize int
	fs       procfs.FS

	scrapeFailures prometheus.Counter

	ioRCharGauge               *prometheus.GaugeVec
	ioWCharGauge               *prometheus.GaugeVec
	ioSyscRGauge               *prometheus.GaugeVec
	ioSyscWGauge               *prometheus.GaugeVec
	ioReadBytesGauge           *prometheus.GaugeVec
	ioWriteBytesGauge          *prometheus.GaugeVec
	ioCancelledWriteBytesGauge *prometheus.GaugeVec
	minfltGauge                *prometheus.GaugeVec
	cminfltGauge               *prometheus.GaugeVec
	majfltGauge                *prometheus.GaugeVec
	cmajfltGauge               *prometheus.GaugeVec
	utimeGauge                 *prometheus.GaugeVec
	stimeGauge                 *prometheus.GaugeVec
	cutimeGauge                *prometheus.GaugeVec
	cstimeGauge                *prometheus.GaugeVec
	niceGauge                  *prometheus.GaugeVec
	numThreadsGauge            *prometheus.GaugeVec
	startTimeGauge             *prometheus.GaugeVec
	vsizeGauge                 *prometheus.GaugeVec
	rssGauge                   *prometheus.GaugeVec
}

func NewExporter(username *string, filter *string, procfsPath string) (*Exporter, error) {
	var uid *uint32 = nil
	if *username != "" {
		usr, err := user.Lookup(*username)
		if err != nil {
			return nil, err
		}

		tmpUid, err := strconv.ParseUint(usr.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		tmpUid32 := uint32(tmpUid)

		uid = &tmpUid32

		log.Info("User: %s UID: %d\n", *username, uid)
	}

	var filterRegex *regexp.Regexp = nil
	if filter != nil {
		log.Infof("Filter: %s", *filter)
		re, err := regexp.Compile(*filter)
		if err != nil {
			log.Fatal(err)
		}
		filterRegex = re
	}

	fs, err := procfs.NewFS(procfsPath)
	if err != nil {
		return nil, err
	}

	procStat, err := fs.NewStat()
	if err != nil {
		return nil, err
	}

	labelNames := []string{"pid", "comm", "cmdline"}

	return &Exporter{
		uid:         uid,
		filterRegex: filterRegex,
		fs:          fs,
		bootTime:    float64(procStat.BootTime),
		pagesize:    os.Getpagesize(),
		scrapeFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrape_failures_total",
			Help:      "Number of errors while scraping apache.",
		}),

		ioRCharGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_rchar",
				Help: "characters read",
			},
			labelNames,
		),
		ioWCharGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_wchar",
				Help: "characters written",
			},
			labelNames,
		),
		ioSyscRGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_syscr",
				Help: "read syscalls",
			},
			labelNames,
		),
		ioSyscWGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_syscw",
				Help: "write syscalls",
			},
			labelNames,
		),
		ioReadBytesGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_readbytes",
				Help: "bytes read",
			},
			labelNames,
		),
		ioWriteBytesGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_writebytes",
				Help: "bytes written",
			},
			labelNames,
		),
		ioCancelledWriteBytesGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procio_cancelledwritebytes",
				Help: "cancelled write bytes",
			},
			labelNames,
		),

		minfltGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_minflt",
				Help: "The number of minor faults the process has made which have not required loading a memory page from disk",
			},
			labelNames,
		),
		cminfltGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_cminflt",
				Help: "The number of minor faults that the process's waited-for children have made",
			},
			labelNames,
		),
		majfltGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_majflt",
				Help: "The number of major faults that the process's waited-for children have made",
			},
			labelNames,
		),
		cmajfltGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_cmajflt",
				Help: "The number of major faults that the process's waited-for children have made",
			},
			labelNames,
		),
		utimeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_utime",
				Help: "Amount of time that this process has been scheduled in user mode, measured in clock ticks.",
			},
			labelNames,
		),
		stimeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_stime",
				Help: "Amount of time that this process has been scheduled in kernel mode, measured in clock ticks.",
			},
			labelNames,
		),
		cutimeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_cutime",
				Help: "Amount of time that this process's waited-for children have been scheduled in user mode, measured in clock ticks.",
			},
			labelNames,
		),
		cstimeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_cstime",
				Help: "Amount of time that this process's waited-for children have been scheduled in kernel mode, measured in clock ticks.",
			},
			labelNames,
		),
		niceGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_nice",
				Help: "The nice value, a value in the range 19 (low priority) to -20 (high priority)",
			},
			labelNames,
		),
		numThreadsGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_numthreads",
				Help: "Number of threads in this process",
			},
			labelNames,
		),
		startTimeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_starttime_epoch",
				Help: "The time the process started in epoch seconds",
			},
			labelNames,
		),
		vsizeGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_vsize",
				Help: "Virtual memory size in bytes",
			},
			labelNames,
		),
		rssGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "procstat_rss",
				Help: "Resident set size in bytes",
			},
			labelNames,
		),
	}, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.scrapeFailures.Describe(ch)

	e.ioRCharGauge.Describe(ch)
	e.ioWCharGauge.Describe(ch)
	e.ioSyscRGauge.Describe(ch)
	e.ioSyscWGauge.Describe(ch)
	e.ioReadBytesGauge.Describe(ch)
	e.ioWriteBytesGauge.Describe(ch)
	e.ioCancelledWriteBytesGauge.Describe(ch)
	e.minfltGauge.Describe(ch)
	e.cminfltGauge.Describe(ch)
	e.majfltGauge.Describe(ch)
	e.cmajfltGauge.Describe(ch)
	e.utimeGauge.Describe(ch)
	e.stimeGauge.Describe(ch)
	e.cutimeGauge.Describe(ch)
	e.cstimeGauge.Describe(ch)
	e.niceGauge.Describe(ch)
	e.numThreadsGauge.Describe(ch)
	e.startTimeGauge.Describe(ch)
	e.vsizeGauge.Describe(ch)
	e.rssGauge.Describe(ch)
}

func (e *Exporter) collect(ch chan<- prometheus.Metric) error {
	procs, err := e.fs.AllProcs()
	if err != nil {
		return err
	}

	for _, proc := range procs {
		if e.uid != nil {
			fi, err := os.Stat(e.fs.Path(fmt.Sprintf("/%d/stat", proc.PID)))
			if err != nil {
				log.Error(err)
				continue
			}

			uid := fi.Sys().(*syscall.Stat_t).Uid
			if e.uid != nil && *e.uid != uid {
				continue
			}
		}

		stat, err := proc.NewStat()
		if err != nil {
			log.Info(err)
			continue
		}

		if e.filterRegex != nil {
			if !e.filterRegex.MatchString(stat.Comm) {
				continue
			}
		}

		cmdline, err := proc.CmdLine()
		if err != nil {
			log.Info(err)
			continue
		}
		sCmdline := strings.Join(cmdline, " ")

		labels := []string{strconv.Itoa(proc.PID), stat.Comm, sCmdline}

		io, err := proc.NewIO()
		if err != nil {
			log.Info(err)
		} else {
			e.ioRCharGauge.WithLabelValues(labels...).Set(float64(io.RChar))
			e.ioWCharGauge.WithLabelValues(labels...).Set(float64(io.WChar))
			e.ioSyscRGauge.WithLabelValues(labels...).Set(float64(io.SyscR))
			e.ioSyscWGauge.WithLabelValues(labels...).Set(float64(io.SyscW))
			e.ioReadBytesGauge.WithLabelValues(labels...).Set(float64(io.ReadBytes))
			e.ioWriteBytesGauge.WithLabelValues(labels...).Set(float64(io.WriteBytes))
			e.ioCancelledWriteBytesGauge.WithLabelValues(labels...).Set(float64(io.CancelledWriteBytes))
		}

		// metrics data from /proc/$$/stat
		// see https://github.com/prometheus/procfs/blob/master/proc_stat.go
		e.minfltGauge.WithLabelValues(labels...).Set(float64(stat.MinFlt))
		e.cminfltGauge.WithLabelValues(labels...).Set(float64(stat.CMinFlt))
		e.majfltGauge.WithLabelValues(labels...).Set(float64(stat.MajFlt))
		e.cmajfltGauge.WithLabelValues(labels...).Set(float64(stat.CMajFlt))
		e.utimeGauge.WithLabelValues(labels...).Set(float64(stat.UTime))
		e.stimeGauge.WithLabelValues(labels...).Set(float64(stat.STime))
		e.cutimeGauge.WithLabelValues(labels...).Set(float64(stat.CUTime))
		e.cstimeGauge.WithLabelValues(labels...).Set(float64(stat.CSTime))
		e.niceGauge.WithLabelValues(labels...).Set(float64(stat.Nice))
		e.numThreadsGauge.WithLabelValues(labels...).Set(float64(stat.NumThreads))
		e.startTimeGauge.WithLabelValues(labels...).Set(e.bootTime + float64(stat.Starttime)/userHZ)
		e.vsizeGauge.WithLabelValues(labels...).Set(float64(stat.VSize))
		e.rssGauge.WithLabelValues(labels...).Set(float64(stat.RSS * e.pagesize))
	}

	e.ioRCharGauge.Collect(ch)
	e.ioWCharGauge.Collect(ch)
	e.ioSyscRGauge.Collect(ch)
	e.ioSyscWGauge.Collect(ch)
	e.ioReadBytesGauge.Collect(ch)
	e.ioWriteBytesGauge.Collect(ch)
	e.ioCancelledWriteBytesGauge.Collect(ch)
	e.minfltGauge.Collect(ch)
	e.cminfltGauge.Collect(ch)
	e.majfltGauge.Collect(ch)
	e.cmajfltGauge.Collect(ch)
	e.utimeGauge.Collect(ch)
	e.stimeGauge.Collect(ch)
	e.cutimeGauge.Collect(ch)
	e.cstimeGauge.Collect(ch)
	e.niceGauge.Collect(ch)
	e.numThreadsGauge.Collect(ch)
	e.startTimeGauge.Collect(ch)
	e.vsizeGauge.Collect(ch)
	e.rssGauge.Collect(ch)

	return nil
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()
	if err := e.collect(ch); err != nil {
		log.Infof("Error getting process info: %s", err)
		e.scrapeFailures.Inc()
		e.scrapeFailures.Collect(ch)
	}
	return
}

func main() {
	flag.Parse()

	if *versionFlg {
		fmt.Fprintf(os.Stderr, "%s version %s\n", os.Args[0], version)

		os.Exit(0)
	}

	exporter, err := NewExporter(userOpt, filter, *procfsPath)
	if err != nil {
		log.Fatal(err)
	}
	prometheus.MustRegister(exporter)

	log.Infof("Listen: %s, Pid: %d", *addr, os.Getpid())

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", prometheus.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
