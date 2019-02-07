package kinesis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kinesis"
	consumer "github.com/harlow/kinesis-consumer"
	"github.com/harlow/kinesis-consumer/checkpoint/ddb"

	"github.com/influxdata/telegraf"
	internalaws "github.com/influxdata/telegraf/internal/config/aws"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/parsers"
)

type (
	DynamoDB struct {
		AppName   string `toml:"app_name"`
		TableName string `toml:"table_name"`
	}

	KinesisConsumer struct {
		Region                 string    `toml:"region"`
		AccessKey              string    `toml:"access_key"`
		SecretKey              string    `toml:"secret_key"`
		RoleARN                string    `toml:"role_arn"`
		Profile                string    `toml:"profile"`
		Filename               string    `toml:"shared_credential_file"`
		Token                  string    `toml:"token"`
		EndpointURL            string    `toml:"endpoint_url"`
		StreamName             string    `toml:"streamname"`
		ShardIteratorType      string    `toml:"shard_iterator_type"`
		DynamoDB               *DynamoDB `toml:"checkpoint_dynamodb"`
		MaxUndeliveredMessages int       `toml:"max_undelivered_messages"`

		consumer *consumer.Consumer
		parser   parsers.Parser
		ctx      context.Context
		cancel   context.CancelFunc

		checkpoint    consumer.Checkpoint
		checkpoints   map[string]checkpoint
		records       map[telegraf.TrackingID]string
		checkpointTex sync.Mutex
		recordsTex    sync.Mutex
		wg            sync.WaitGroup

		lastSeqNum string
	}

	checkpoint struct {
		streamName string
		shardID    string
	}
)

const (
	defaultMaxUndeliveredMessages = 1000
	maxSeq                        = "99999999999999999999999999999999999999999999999999999999"
)

var sampleConfig = `
  ## Amazon REGION of kinesis endpoint.
  region = "ap-southeast-2"

  ## Amazon Credentials
  ## Credentials are loaded in the following order
  ## 1) Assumed credentials via STS if role_arn is specified
  ## 2) explicit credentials from 'access_key' and 'secret_key'
  ## 3) shared profile from 'profile'
  ## 4) environment variables
  ## 5) shared credentials file
  ## 6) EC2 Instance Profile
  # access_key = ""
  # secret_key = ""
  # token = ""
  # role_arn = ""
  # profile = ""
  # shared_credential_file = ""

  ## Endpoint to make request against, the correct endpoint is automatically
  ## determined and this option should only be set if you wish to override the
  ## default.
  ##   ex: endpoint_url = "http://localhost:8000"
  # endpoint_url = ""

  ## Kinesis StreamName must exist prior to starting telegraf.
  streamname = "StreamName"

  ## Shard iterator type (only 'TRIM_HORIZON' and 'LATEST' currently supported)
  # shard_iterator_type = "TRIM_HORIZON"

  ## Maximum messages to read from the broker that have not been written by an
  ## output.  For best throughput set based on the number of metrics within
  ## each message and the size of the output's metric_batch_size.
  ##
  ## For example, if each message from the queue contains 10 metrics and the
  ## output metric_batch_size is 1000, setting this to 100 will ensure that a
  ## full batch is collected and the write is triggered immediately without
  ## waiting until the next flush_interval.
  # max_undelivered_messages = 1000

  ## Data format to consume.
  ## Each data format has its own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md
  data_format = "influx"

  ## Optional
  ## Configuration for a dynamodb checkpoint
  [inputs.kinesis_consumer.checkpoint_dynamodb]
	## unique name for this consumer
	app_name = "default"
	table_name = "default"
`

func (k *KinesisConsumer) SampleConfig() string {
	return sampleConfig
}

func (k *KinesisConsumer) Description() string {
	return "Configuration for the AWS Kinesis input."
}

func (k *KinesisConsumer) SetParser(parser parsers.Parser) {
	k.parser = parser
}

func (k *KinesisConsumer) connect() error {
	credentialConfig := &internalaws.CredentialConfig{
		Region:      k.Region,
		AccessKey:   k.AccessKey,
		SecretKey:   k.SecretKey,
		RoleARN:     k.RoleARN,
		Profile:     k.Profile,
		Filename:    k.Filename,
		Token:       k.Token,
		EndpointURL: k.EndpointURL,
	}
	configProvider := credentialConfig.Credentials()
	client := kinesis.New(configProvider)

	_, err := client.DescribeStreamSummary(&kinesis.DescribeStreamSummaryInput{
		StreamName: aws.String(k.StreamName),
	})

	k.checkpoint = &noopCheckpoint{}
	if k.DynamoDB != nil {
		k.checkpoint, err = ddb.New(
			k.DynamoDB.AppName,
			k.DynamoDB.TableName,
			ddb.WithDynamoClient(dynamodb.New((&internalaws.CredentialConfig{
				Region:      k.Region,
				AccessKey:   k.AccessKey,
				SecretKey:   k.SecretKey,
				RoleARN:     k.RoleARN,
				Profile:     k.Profile,
				Filename:    k.Filename,
				Token:       k.Token,
				EndpointURL: k.EndpointURL,
			}).Credentials())),
			ddb.WithMaxInterval(time.Second*10),
		)
		if err != nil {
			return err
		}
	}

	consumer, err := consumer.New(
		k.StreamName,
		consumer.WithClient(client),
		consumer.WithShardIteratorType(k.ShardIteratorType),
		consumer.WithCheckpoint(k),
	)
	if err != nil {
		return err
	}

	k.consumer = consumer
	return nil
}

func (k *KinesisConsumer) Start(ac telegraf.Accumulator) error {
	if k.consumer == nil {
		err := k.connect()
		if err != nil {
			return err
		}
	}

	acc := ac.WithTracking(k.MaxUndeliveredMessages)
	k.records = make(map[telegraf.TrackingID]string, k.MaxUndeliveredMessages)
	k.checkpoints = make(map[string]checkpoint, k.MaxUndeliveredMessages)
	sem := make(chan struct{}, k.MaxUndeliveredMessages)

	ctx := context.Background()
	ctx, k.cancel = context.WithCancel(ctx)

	go func() {
		err := k.consumer.Scan(ctx, func(r *consumer.Record) consumer.ScanStatus {
			sem <- struct{}{}
			err := k.onMessage(acc, r)
			if err != nil {
				return consumer.ScanStatus{Error: err}
			}

			return consumer.ScanStatus{}
		})
		if err != nil {
			log.Printf("E! Scan encounterred an error - %s", err.Error())
			k.consumer = nil
		}
	}()

	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		k.onDelivery(ctx, acc, sem)
	}()

	return nil
}

func (k *KinesisConsumer) onMessage(acc telegraf.TrackingAccumulator, r *consumer.Record) error {
	metrics, err := k.parser.Parse(r.Data)
	if err != nil {
		return err
	}

	k.recordsTex.Lock()
	id := acc.AddTrackingMetricGroup(metrics)
	k.records[id] = *r.SequenceNumber
	k.recordsTex.Unlock()

	return nil
}

func (k *KinesisConsumer) onDelivery(ctx context.Context, acc telegraf.TrackingAccumulator, sem chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case info := <-acc.Delivered():
			k.recordsTex.Lock()
			sequenceNum, ok := k.records[info.ID()]
			if !ok {
				k.recordsTex.Unlock()
				continue
			}
			<-sem
			delete(k.records, info.ID())
			k.recordsTex.Unlock()

			if info.Delivered() {
				k.checkpointTex.Lock()
				chk, ok := k.checkpoints[sequenceNum]
				if !ok {
					k.checkpointTex.Unlock()
					continue
				}
				delete(k.checkpoints, sequenceNum)
				k.checkpointTex.Unlock()

				// at least once
				if sequenceNum > k.lastSeqNum {
					continue
				}

				k.lastSeqNum = sequenceNum
				k.checkpoint.Set(chk.streamName, chk.shardID, sequenceNum)
			} else {
				log.Println("D! Metric group failed to process")
			}
		}
	}
}

func (k *KinesisConsumer) Stop() {
	k.cancel()
	k.wg.Wait()
}

func (k *KinesisConsumer) Gather(acc telegraf.Accumulator) error {
	if k.consumer == nil {
		return k.connect()
	}
	k.lastSeqNum = maxSeq

	return nil
}

// Get wraps the checkpoint's Get function (called by consumer library)
func (k *KinesisConsumer) Get(streamName, shardID string) (string, error) {
	return k.checkpoint.Get(streamName, shardID)
}

// Set wraps the checkpoint's Set function (called by consumer library)
func (k *KinesisConsumer) Set(streamName, shardID, sequenceNumber string) error {
	if sequenceNumber == "" {
		return fmt.Errorf("sequence number should not be empty")
	}

	k.checkpointTex.Lock()
	k.checkpoints[sequenceNumber] = checkpoint{streamName: streamName, shardID: shardID}
	k.checkpointTex.Unlock()

	return nil
}

type noopCheckpoint struct{}

func (n noopCheckpoint) Set(string, string, string) error   { return nil }
func (n noopCheckpoint) Get(string, string) (string, error) { return "", nil }

func init() {
	inputs.Add("kinesis_consumer", func() telegraf.Input {
		return &KinesisConsumer{
			ShardIteratorType:      "TRIM_HORIZON",
			MaxUndeliveredMessages: defaultMaxUndeliveredMessages,
			lastSeqNum:             maxSeq,
		}
	})
}