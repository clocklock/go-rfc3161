package rfc3161

import (
	"mime"
)

// Configuration
// Set InitMimeTypes to initialize mimetimes for timestamp-query and timestamp-reply
var InitMimeTypes bool

func SetMimeTypes() error {
	err := mime.AddExtensionType(".tsq", "application/timestamp-query")
	if err != nil {
		return err
	}

	err = mime.AddExtensionType(".tsr", "application/timestamp-reply")
	if err != nil {
		return err
	}

	return nil
}

func init() {
	if InitMimeTypes {
		err := SetMimeTypes()
		if err != nil {
			panic(err)
		}
	}
}
