package dto

// ---------------------------------------------------------------------------
// Attachment DTOs — request/response models for attachment endpoints.
// ---------------------------------------------------------------------------

// AttachmentRequestDTO is sent in POST /ciphers/{id}/attachment/v2 request bodies.
// JSON tags use lower-camel as required by the Bitwarden API.
type AttachmentRequestDTO struct {
	FileName              string `json:"fileName"`
	Key                   string `json:"key"`
	FileSize              int64  `json:"fileSize"`
	AdminRequest          bool   `json:"adminRequest"`
	LastKnownRevisionDate string `json:"lastKnownRevisionDate,omitempty"`
}

// AttachmentResponseDTO is returned from GET
// /ciphers/{cipherId}/attachment/{attachmentId}.
type AttachmentResponseDTO struct {
	ID       string `json:"Id"`
	URL      string `json:"Url"`
	FileName string `json:"FileName"`
	Key      string `json:"Key"`
	Size     int64  `json:"Size"`
	SizeName string `json:"SizeName"`
}

// AttachmentUploadDataResponseDTO is returned from POST
// /ciphers/{id}/attachment/v2 and GET /ciphers/{id}/attachment/{attachmentId}/renew.
type AttachmentUploadDataResponseDTO struct {
	AttachmentID       string              `json:"AttachmentId"`
	FileUploadType     int                 `json:"FileUploadType"`
	CipherResponse     *CipherMiniResponse `json:"CipherResponse,omitempty"`
	CipherMiniResponse *CipherMiniResponse `json:"CipherMiniResponse,omitempty"`
	URL                *string             `json:"Url,omitempty"`
}

// CipherMiniResponse is a shorthand cipher object used inside attachment
// upload responses (CipherResponse / CipherMiniResponse).
type CipherMiniResponse struct {
	ID           string `json:"Id"`
	RevisionDate string `json:"RevisionDate"`
}

// DeleteAttachmentResponseDTO is returned from DELETE
// /ciphers/{id}/attachment/{attachmentId}.
type DeleteAttachmentResponseDTO struct {
	Cipher *CipherMiniResponseExtended `json:"Cipher,omitempty"`
}

// CipherMiniResponseExtended extends the mini cipher with extra fields
// returned by the delete attachment endpoint (e.g. Attachments).
type CipherMiniResponseExtended struct {
	ID           string `json:"Id"`
	RevisionDate string `json:"RevisionDate"`
	// Attachments may be present in delete response after removal.
	Attachments []AttachmentResponseDTO `json:"Attachments,omitempty"`
}
