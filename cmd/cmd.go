package main

import (
	"fmt"
	"syscall"

	"github.com/miekg/pkcs11"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/stlaz/pkcs11-crypto/api"
	"github.com/stlaz/pkcs11-crypto/pkg/keys"
	"github.com/stlaz/pkcs11-crypto/pkg/token"
)

type pkcs11Options struct {
	modulePath string
	tokenSlot  uint
}

func NewPKCS11Options() *pkcs11Options {
	return &pkcs11Options{}
}

func (o *pkcs11Options) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&o.modulePath, "module", "m", "", "path to the PKCS11 module implementation")
	flags.UintVarP(&o.tokenSlot, "slot", "p", 0, "token slot number")
}

func (o *pkcs11Options) Validate() []error {
	errs := []error{}

	if len(o.modulePath) == 0 {
		errs = append(errs, fmt.Errorf("--module must be set"))
	}

	return errs
}

func (o *pkcs11Options) ApplyTo(config *cryptoConfig) error {
	config.pkcs11Context = pkcs11.New(o.modulePath)

	config.slot = o.tokenSlot

	return nil
}

type cryptoConfig struct {
	pkcs11Context *pkcs11.Ctx
	slot          uint
}

func NewCryptoUtilCommand() *cobra.Command {
	opts := NewPKCS11Options()

	cmd := &cobra.Command{
		Use:          "cryptoutil",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if errs := opts.Validate(); len(errs) > 0 {
				return fmt.Errorf("wrong options: %v", errs)
			}

			config := &cryptoConfig{}
			if err := opts.ApplyTo(config); err != nil {
				return fmt.Errorf("failed to create config: %w", err)
			}

			return run(config)
		},
	}

	fs := cmd.Flags()
	opts.AddFlags(fs)

	return cmd
}

func run(config *cryptoConfig) error {
	p11Context := config.pkcs11Context
	if err := p11Context.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize PKCS11 context: %w", err)
	}
	defer p11Context.Finalize()

	// TODO: need to study the sessions more
	// - 5.6 at https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
	// - https://www.cryptsoft.com/pkcs11doc/v100/pkcs11__all_8h.html seems useful, too

	// yubikey 4 with yubico PKCS#11 module fails unless you list slots before
	// opening a session. The OpenSC module works without it though
	// TODO: why, does the spec mention anything about this?
	availableSlots := token.ListAvailableSlots(p11Context)

	session, err := p11Context.OpenSession(config.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		if token.IsInvalidSlotID(err) {
			return fmt.Errorf("slot %d is invalid (%w), available slots: %v", config.slot, err, availableSlots)
		}
		return fmt.Errorf("failed to open a session with the token: %w", err)
	}
	defer p11Context.CloseSession(session)

	p11session := api.WrapSession(p11Context, session)

	// TODO: reconsider - if the user is not logged in, we can still create public objects
	fmt.Printf("please enter pin for slot %d: ", config.slot)
	passwd, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to retrieve pin: %w", err)
	}

	// we assume an initialized token, not logging in as a SO (security officer)
	// TODO: YubiKey 4 actually requires SO to generate an RSA key, study what SO normally does?
	if err := p11session.Login(session, pkcs11.CKU_SO, string(passwd)); err != nil {
		return fmt.Errorf("login to the token failed: %w", err)
	}

	mlist, err := p11session.GetMechanismList(config.slot)
	if err != nil {
		return err
	}

	for _, minfo := range mlist {
		fmt.Printf("%x - %x\n", minfo.Mechanism, minfo.Parameter)
	}

	// YubiKey appears to insist on Key ID being set but IDK how to get ID range
	// in a generic PKCS#11 manner. There may not be a way.
	// 60 is already too great for YubiKey.
	// TODO: would setting a label be enough, instead of ID?
	rsaKey, err := keys.GenerateRSAKey(p11session, 10, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate an RSA key: %w", err)
	}

	if err := rsaKey.Destroy(p11Context, session); err != nil {
		return fmt.Errorf("failed to destroy an RSA key: %w", err)
	}

	// see https://github.com/thalesignite/crypto11 to check how to do this crypto properly
	return nil
}
