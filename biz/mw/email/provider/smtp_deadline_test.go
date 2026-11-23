package provider

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestSMTPDeadlineIncludesGreetingAndCommands(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, encrypted := range []bool{false, true} {
		for _, greeting := range []bool{false, true} {
			t.Run(strconv.FormatBool(encrypted)+"/greeting="+strconv.FormatBool(greeting), func(t *testing.T) {
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()
				defer serverConn.Close()
				if encrypted {
					server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
					client := tls.Client(clientConn, &tls.Config{ServerName: "localhost", RootCAs: roots})
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- server.HandshakeContext(ctx) }()
					if err := client.HandshakeContext(ctx); err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					clientConn, serverConn = client, server
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					if greeting {
						_, _ = serverConn.Write([]byte("220 localhost SMTP\r\n"))
					}
					// Accept input but never answer SMTP commands.
					reader := bufio.NewReader(serverConn)
					for {
						if _, err := reader.ReadString('\n'); err != nil {
							return
						}
					}
				}()
				start := time.Now()
				client, cleanup, err := smtpClient(context.Background(), clientConn, "localhost", start.Add(100*time.Millisecond))
				if greeting {
					if err != nil {
						t.Fatal(err)
					}
					err = client.Mail("sender@example.invalid")
					cleanup()
				}
				if err == nil {
					t.Fatal("stalled SMTP did not time out")
				}
				if time.Since(start) > 2*time.Second {
					t.Fatal("deadline did not bound SMTP IO")
				}
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("connection not closed")
				}
			})
		}
	}
}

func TestSMTPSendUsesEarlierContextOrConfigTimeout(t *testing.T) {
	for _, contextEarlier := range []bool{false, true} {
		t.Run(strconv.FormatBool(contextEarlier), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var b [1]byte
				_, _ = conn.Read(b[:]) // no greeting
			}()
			short, long := 100*time.Millisecond, 3*time.Second
			configTimeout, contextTimeout := short, long
			if contextEarlier {
				configTimeout, contextTimeout = long, short
			}
			ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
			defer cancel()
			sender := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, From: "sender@example.invalid", Timeout: configTimeout})
			start := time.Now()
			err = sender.Send(ctx, &Message{To: []string{"recipient@example.invalid"}, Subject: "test", Text: "test"})
			if err == nil || time.Since(start) > 2*time.Second {
				t.Fatalf("earlier deadline ignored: %v", err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("greeting failure leaked connection")
			}
		})
	}
}
