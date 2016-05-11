package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	interval   = flag.Duration("interval", 1*time.Second, "The interval for polling.")
	filter     = flag.String("filter", "", "Commandline filter")
	versionFlg = flag.Bool("version", false, "Show version number")
)

var (
	labelNames = []string{"pid", "comm", "cmdline"}

	ioRCharGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_rchar",
			Help: "characters read",
		},
		labelNames,
	)
	ioWCharGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_wchar",
			Help: "characters written",
		},
		labelNames,
	)
	ioSyscRGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_syscr",
			Help: "read syscalls",
		},
		labelNames,
	)
	ioSyscWGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_syscw",
			Help: "write syscalls",
		},
		labelNames,
	)
	ioReadBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_readbytes",
			Help: "bytes read",
		},
		labelNames,
	)
	ioWriteBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_writebytes",
			Help: "bytes written",
		},
		labelNames,
	)
	ioCancelledWriteBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procio_cancelledwritebytes",
			Help: "cancelled write bytes",
		},
		labelNames,
	)

	minfltGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_minflt",
			Help: "The number of minor faults the process has made which have not required loading a memory page from disk",
		},
		labelNames,
	)
	cminfltGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_cminflt",
			Help: "The number of minor faults that the process's waited-for children have made",
		},
		labelNames,
	)
	majfltGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_majflt",
			Help: "The number of major faults that the process's waited-for children have made",
		},
		labelNames,
	)
	cmajfltGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_cmajflt",
			Help: "The number of major faults that the process's waited-for children have made",
		},
		labelNames,
	)
	utimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_utime",
			Help: "Amount of time that this process has been scheduled in user mode, measured in clock ticks.",
		},
		labelNames,
	)
	stimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_stime",
			Help: "Amount of time that this process has been scheduled in kernel mode, measured in clock ticks.",
		},
		labelNames,
	)
	cutimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_cutime",
			Help: "Amount of time that this process's waited-for children have been scheduled in user mode, measured in clock ticks.",
		},
		labelNames,
	)
	cstimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_cstime",
			Help: "Amount of time that this process's waited-for children have been scheduled in kernel mode, measured in clock ticks.",
		},
		labelNames,
	)
	niceGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_nice",
			Help: "The nice value, a value in the range 19 (low priority) to -20 (high priority)",
		},
		labelNames,
	)
	numThreadsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_numthreads",
			Help: "Number of threads in this process",
		},
		labelNames,
	)
	startTimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_starttime_epoch",
			Help: "The time the process started in epoch seconds",
		},
		labelNames,
	)
	vsizeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_vsize",
			Help: "Virtual memory size in bytes",
		},
		labelNames,
	)
	rssGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "procstat_rss",
			Help: "Resident set size in bytes",
		},
		labelNames,
	)
)

func init() {
	prometheus.MustRegister(ioRCharGauge)
	prometheus.MustRegister(ioWCharGauge)
	prometheus.MustRegister(ioSyscRGauge)
	prometheus.MustRegister(ioSyscWGauge)
	prometheus.MustRegister(ioReadBytesGauge)
	prometheus.MustRegister(ioWriteBytesGauge)
	prometheus.MustRegister(ioCancelledWriteBytesGauge)

	prometheus.MustRegister(minfltGauge)
	prometheus.MustRegister(cminfltGauge)
	prometheus.MustRegister(majfltGauge)
	prometheus.MustRegister(cmajfltGauge)
	prometheus.MustRegister(utimeGauge)
	prometheus.MustRegister(stimeGauge)
	prometheus.MustRegister(cutimeGauge)
	prometheus.MustRegister(cstimeGauge)
	prometheus.MustRegister(niceGauge)
	prometheus.MustRegister(numThreadsGauge)
	prometheus.MustRegister(startTimeGauge)
	prometheus.MustRegister(vsizeGauge)
	prometheus.MustRegister(rssGauge)
}

func main() {
	flag.Parse()

	if *versionFlg {
		fmt.Fprintf(os.Stderr, "%s version %s\n", os.Args[0], version)

		os.Exit(0)
	}

	var filterRegex *regexp.Regexp = nil
	if filter != nil {
		log.Printf("Filter: %s\n", *filter)
		re, err := regexp.Compile(*filter)
		if err != nil {
			log.Fatal(err)
		}
		filterRegex = re
	}

	procStat, err := procfs.NewStat()
	if err != nil {
		log.Fatal(err)
	}
	bootTime := float64(procStat.BootTime)
	pagesize := os.Getpagesize()

	go func() {
		for {
			procs, err := procfs.AllProcs()
			if err != nil {
				log.Print(err)
				continue
			}
			for _, proc := range procs {
				stat, err := proc.NewStat()
				if err != nil {
					// log.Print(err)
					continue
				}

				cmdline, err := proc.CmdLine()
				if err != nil {
					log.Print(err)
					continue
				}
				sCmdline := strings.Join(cmdline, " ")

				if filterRegex != nil {
					if !filterRegex.MatchString(sCmdline) {
						continue
					}
				}

				labels := []string{strconv.Itoa(proc.PID), stat.Comm, sCmdline}

				io, err := proc.NewIO()
				if err != nil {
					// This makes lot of noisy logging output when this process run on non-root user.
					// log.Print(err)
				} else {
					ioRCharGauge.WithLabelValues(labels...).Set(float64(io.RChar))
					ioWCharGauge.WithLabelValues(labels...).Set(float64(io.WChar))
					ioSyscRGauge.WithLabelValues(labels...).Set(float64(io.SyscR))
					ioSyscWGauge.WithLabelValues(labels...).Set(float64(io.SyscW))
					ioReadBytesGauge.WithLabelValues(labels...).Set(float64(io.ReadBytes))
					ioWriteBytesGauge.WithLabelValues(labels...).Set(float64(io.WriteBytes))
					ioCancelledWriteBytesGauge.WithLabelValues(labels...).Set(float64(io.CancelledWriteBytes))
				}

				// metrics data from /proc/$$/stat
				// see https://github.com/prometheus/procfs/blob/master/proc_stat.go
				minfltGauge.WithLabelValues(labels...).Set(float64(stat.MinFlt))
				cminfltGauge.WithLabelValues(labels...).Set(float64(stat.CMinFlt))
				majfltGauge.WithLabelValues(labels...).Set(float64(stat.MajFlt))
				cmajfltGauge.WithLabelValues(labels...).Set(float64(stat.CMajFlt))
				utimeGauge.WithLabelValues(labels...).Set(float64(stat.UTime))
				niceGauge.WithLabelValues(labels...).Set(float64(stat.Nice))
				numThreadsGauge.WithLabelValues(labels...).Set(float64(stat.NumThreads))
				startTimeGauge.WithLabelValues(labels...).Set(bootTime + float64(stat.Starttime)/userHZ)
				vsizeGauge.WithLabelValues(labels...).Set(float64(stat.VSize))
				rssGauge.WithLabelValues(labels...).Set(float64(stat.RSS * pagesize))
			}
			time.Sleep(*interval)
		}
	}()

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", prometheus.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
