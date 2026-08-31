// Package main implements the Zabbix DNF plugin.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/logging"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"

	"golang.zabbix.com/sdk/log"
	"golang.zabbix.com/sdk/plugin"
	"golang.zabbix.com/sdk/plugin/container"
)

const (
	pluginName          = "DNF"
	metricGet           = "dnf.get"
	metricPackagesGet   = "packages.get"
	metricAdvisoriesGet = "dnf.advisories.get"
	testArg             = "--test"
	collectionTimeout   = 2 * time.Minute
)

func main() {
	err := run(
		os.Args[1:],
		func() error { return runCollection(os.Stdout, os.Stderr) },
		runAgent,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zabbix-dnf-plugin: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, testMode, agentMode func() error) error {
	if len(args) > 0 && args[0] == testArg {
		if len(args) != 1 {
			return fmt.Errorf("%s does not accept arguments", testArg)
		}

		return testMode()
	}

	return agentMode()
}

func runCollection(stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	pluginInstance := newPlugin(
		command.Runner{},
		slog.New(slog.NewTextHandler(stderr, nil)),
	)

	return collectAndWrite(ctx, stdout, pluginInstance.collect)
}

func collectAndWrite(
	parent context.Context,
	stdout io.Writer,
	collect func(context.Context) (results.Payload, error),
) error {
	ctx, cancel := context.WithTimeout(parent, collectionTimeout)
	defer cancel()

	started := time.Now()

	payload, err := collect(ctx)
	if err != nil {
		return err
	}
	payload.Collection.DurationMS = time.Since(started).Milliseconds()

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(payload)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	return nil
}

func runAgent() error {
	ctx, stopSignals := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignals()

	pluginInstance := newPlugin(command.Runner{}, nil)
	pluginInstance.Base = plugin.Base{Logger: log.New(pluginName)}

	err := plugin.RegisterMetrics(
		pluginInstance,
		pluginName,
		metricGet,
		"Returns package repositories, available updates, and reboot status.",
		metricPackagesGet,
		"Returns a package-manager-neutral package update snapshot.",
		metricAdvisoriesGet,
		"Returns applicable DNF security advisory intelligence.",
	)
	if err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}

	handler, err := container.NewHandler(pluginName)
	if err != nil {
		return fmt.Errorf("create plugin handler: %w", err)
	}

	// Forward native Zabbix plugin logging to Agent 2.
	pluginInstance.Logger = handler

	pluginInstance.logger = slog.New(logging.NewZabbixHandler(pluginInstance))
	defer pluginInstance.Stop()

	err = executeAgentHandler(ctx, handler.Execute, pluginInstance.Stop)
	if err != nil {
		return fmt.Errorf("execute plugin handler: %w", err)
	}

	return nil
}

func executeAgentHandler(
	ctx context.Context,
	execute func() error,
	shutdown func(),
) error {
	result := make(chan error, 1)
	go func() {
		result <- execute()
	}()

	select {
	case <-ctx.Done():
		shutdown()

		return nil
	case err := <-result:
		return err
	}
}
