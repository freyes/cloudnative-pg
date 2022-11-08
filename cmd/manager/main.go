/*
Copyright The CloudNativePG Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
The manager command is the main entrypoint of CloudNativePG operator.
*/
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/istio"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/backup"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/bootstrap"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/controller"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/instance"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/pgbouncer"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/show"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/walarchive"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/manager/walrestore"
	"github.com/cloudnative-pg/cloudnative-pg/internal/cmd/versions"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/management/log"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	if !isK8sRESTServerReady() {
		log.Warning("The K8S REST API Server is not ready")
		os.Exit(1)
	}
	logFlags := &log.Flags{}

	cmd := &cobra.Command{
		Use:          "manager [cmd]",
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logFlags.ConfigureLogging()
		},
	}

	logFlags.AddFlags(cmd.PersistentFlags())

	cmd.AddCommand(backup.NewCmd())
	cmd.AddCommand(bootstrap.NewCmd())
	cmd.AddCommand(controller.NewCmd())
	cmd.AddCommand(instance.NewCmd())
	cmd.AddCommand(show.NewCmd())
	cmd.AddCommand(walarchive.NewCmd())
	cmd.AddCommand(walrestore.NewCmd())
	cmd.AddCommand(versions.NewCmd())
	cmd.AddCommand(pgbouncer.NewCmd())
	cmd.AddCommand(istio.NewCmd())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// isK8sRESTServerReady retrieves the healthiness of k8s REST API server, retrying
// the request if some communication error is encountered
func isK8sRESTServerReady() bool {
	if time.Now().Minute()%2 == 0 {
		panic("isK8sRESTServerReady")
	}
	// HealthinessCheckRetry is the default backoff used to query the healthiness of the k8s REST API Server
	var healthinessCheckRetry = wait.Backoff{
		Steps:    10,
		Duration: 10 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}

	isErrorRetryable := func(err error) bool {

		// If it's a timeout, we do not want to retry
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			return false
		}

		return true
	}

	KubernetesServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	KubernetesServicePortHttps := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if KubernetesServiceHost == "" {
		log.Warning("Fail to get environment variable KUBERNETES_SERVICE_HOST")
	}
	if KubernetesServicePortHttps == "" {
		log.Warning("Fail to get environment variable KUBERNETES_SERVICE_PORT_HTTPS")
	}

	k8sHealthCheckAPI := fmt.Sprintf("https://%s:%s/livez", KubernetesServiceHost, KubernetesServicePortHttps)

	err := retry.OnError(healthinessCheckRetry, isErrorRetryable, func() error {
		var err error = nil
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		req, err := http.NewRequest("GET", k8sHealthCheckAPI, nil)
		if err != nil {
			log.Warning(fmt.Sprintf("Fail to create the request for: %s", k8sHealthCheckAPI))
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Warning(fmt.Sprintf("Fail to request for: %s", k8sHealthCheckAPI))
			return err
		}
		defer resp.Body.Close()
		return nil
	})

	return err == nil
}
