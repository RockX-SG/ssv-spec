// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.6.1
// source: types/messages.proto

package types

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MessageHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId []byte `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	MsgType   int32  `protobuf:"varint,2,opt,name=msg_type,json=msgType,proto3" json:"msg_type,omitempty"`
	Sender    uint64 `protobuf:"varint,3,opt,name=sender,proto3" json:"sender,omitempty"`
	Receiver  uint64 `protobuf:"varint,4,opt,name=receiver,proto3" json:"receiver,omitempty"`
}

func (x *MessageHeader) Reset() {
	*x = MessageHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MessageHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageHeader) ProtoMessage() {}

func (x *MessageHeader) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageHeader.ProtoReflect.Descriptor instead.
func (*MessageHeader) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{0}
}

func (x *MessageHeader) GetSessionId() []byte {
	if x != nil {
		return x.SessionId
	}
	return nil
}

func (x *MessageHeader) GetMsgType() int32 {
	if x != nil {
		return x.MsgType
	}
	return 0
}

func (x *MessageHeader) GetSender() uint64 {
	if x != nil {
		return x.Sender
	}
	return 0
}

func (x *MessageHeader) GetReceiver() uint64 {
	if x != nil {
		return x.Receiver
	}
	return 0
}

//
// A generic message.
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header    *MessageHeader `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Data      []byte         `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Signature []byte         `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{1}
}

func (x *Message) GetHeader() *MessageHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *Message) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Message) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type Init struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OperatorIDs           []uint64 `protobuf:"varint,1,rep,packed,name=OperatorIDs,proto3" json:"OperatorIDs,omitempty"`
	Threshold             uint64   `protobuf:"varint,2,opt,name=threshold,proto3" json:"threshold,omitempty"`
	WithdrawalCredentials []byte   `protobuf:"bytes,3,opt,name=withdrawal_credentials,json=withdrawalCredentials,proto3" json:"withdrawal_credentials,omitempty"`
	Fork                  []byte   `protobuf:"bytes,4,opt,name=fork,proto3" json:"fork,omitempty"`
}

func (x *Init) Reset() {
	*x = Init{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Init) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Init) ProtoMessage() {}

func (x *Init) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Init.ProtoReflect.Descriptor instead.
func (*Init) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{2}
}

func (x *Init) GetOperatorIDs() []uint64 {
	if x != nil {
		return x.OperatorIDs
	}
	return nil
}

func (x *Init) GetThreshold() uint64 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *Init) GetWithdrawalCredentials() []byte {
	if x != nil {
		return x.WithdrawalCredentials
	}
	return nil
}

func (x *Init) GetFork() []byte {
	if x != nil {
		return x.Fork
	}
	return nil
}

type ParsedInitMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header    *MessageHeader `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Body      *Init          `protobuf:"bytes,2,opt,name=body,proto3" json:"body,omitempty"`
	Signature []byte         `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *ParsedInitMessage) Reset() {
	*x = ParsedInitMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ParsedInitMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ParsedInitMessage) ProtoMessage() {}

func (x *ParsedInitMessage) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ParsedInitMessage.ProtoReflect.Descriptor instead.
func (*ParsedInitMessage) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{3}
}

func (x *ParsedInitMessage) GetHeader() *MessageHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *ParsedInitMessage) GetBody() *Init {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *ParsedInitMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type LocalKeyShare struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index           uint64   `protobuf:"varint,1,opt,name=Index,proto3" json:"Index,omitempty"`
	Threshold       uint64   `protobuf:"varint,2,opt,name=Threshold,proto3" json:"Threshold,omitempty"`
	Committee       []uint64 `protobuf:"varint,3,rep,packed,name=Committee,proto3" json:"Committee,omitempty"`
	SharePublicKeys [][]byte `protobuf:"bytes,4,rep,name=SharePublicKeys,proto3" json:"SharePublicKeys,omitempty"`
	PublicKey       []byte   `protobuf:"bytes,5,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
	SecretShare     []byte   `protobuf:"bytes,6,opt,name=SecretShare,proto3" json:"SecretShare,omitempty"`
}

func (x *LocalKeyShare) Reset() {
	*x = LocalKeyShare{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LocalKeyShare) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LocalKeyShare) ProtoMessage() {}

func (x *LocalKeyShare) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LocalKeyShare.ProtoReflect.Descriptor instead.
func (*LocalKeyShare) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{4}
}

func (x *LocalKeyShare) GetIndex() uint64 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *LocalKeyShare) GetThreshold() uint64 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *LocalKeyShare) GetCommittee() []uint64 {
	if x != nil {
		return x.Committee
	}
	return nil
}

func (x *LocalKeyShare) GetSharePublicKeys() [][]byte {
	if x != nil {
		return x.SharePublicKeys
	}
	return nil
}

func (x *LocalKeyShare) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *LocalKeyShare) GetSecretShare() []byte {
	if x != nil {
		return x.SecretShare
	}
	return nil
}

type PartialSigMsgBody struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signer    uint64 `protobuf:"varint,1,opt,name=Signer,proto3" json:"Signer,omitempty"`
	Root      []byte `protobuf:"bytes,2,opt,name=Root,proto3" json:"Root,omitempty"`
	Signature []byte `protobuf:"bytes,3,opt,name=Signature,proto3" json:"Signature,omitempty"`
}

func (x *PartialSigMsgBody) Reset() {
	*x = PartialSigMsgBody{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PartialSigMsgBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PartialSigMsgBody) ProtoMessage() {}

func (x *PartialSigMsgBody) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PartialSigMsgBody.ProtoReflect.Descriptor instead.
func (*PartialSigMsgBody) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{5}
}

func (x *PartialSigMsgBody) GetSigner() uint64 {
	if x != nil {
		return x.Signer
	}
	return 0
}

func (x *PartialSigMsgBody) GetRoot() []byte {
	if x != nil {
		return x.Root
	}
	return nil
}

func (x *PartialSigMsgBody) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ParsedPartialSigMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header    *MessageHeader     `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Body      *PartialSigMsgBody `protobuf:"bytes,2,opt,name=body,proto3" json:"body,omitempty"`
	Signature []byte             `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *ParsedPartialSigMessage) Reset() {
	*x = ParsedPartialSigMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ParsedPartialSigMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ParsedPartialSigMessage) ProtoMessage() {}

func (x *ParsedPartialSigMessage) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ParsedPartialSigMessage.ProtoReflect.Descriptor instead.
func (*ParsedPartialSigMessage) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{6}
}

func (x *ParsedPartialSigMessage) GetHeader() *MessageHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *ParsedPartialSigMessage) GetBody() *PartialSigMsgBody {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *ParsedPartialSigMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type SignedDepositDataMsgBody struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestID             []byte   `protobuf:"bytes,1,opt,name=RequestID,proto3" json:"RequestID,omitempty"`
	OperatorID            uint64   `protobuf:"varint,2,opt,name=OperatorID,proto3" json:"OperatorID,omitempty"`
	EncryptedShare        []byte   `protobuf:"bytes,3,opt,name=EncryptedShare,proto3" json:"EncryptedShare,omitempty"`
	Committee             []uint64 `protobuf:"varint,4,rep,packed,name=Committee,proto3" json:"Committee,omitempty"`
	Threshold             uint64   `protobuf:"varint,5,opt,name=threshold,proto3" json:"threshold,omitempty"`
	ValidatorPublicKey    []byte   `protobuf:"bytes,6,opt,name=ValidatorPublicKey,proto3" json:"ValidatorPublicKey,omitempty"`
	WithdrawalCredentials []byte   `protobuf:"bytes,7,opt,name=WithdrawalCredentials,proto3" json:"WithdrawalCredentials,omitempty"`
	DepositDataSignature  []byte   `protobuf:"bytes,8,opt,name=DepositDataSignature,proto3" json:"DepositDataSignature,omitempty"`
	OperatorSignature     []byte   `protobuf:"bytes,9,opt,name=OperatorSignature,proto3" json:"OperatorSignature,omitempty"`
}

func (x *SignedDepositDataMsgBody) Reset() {
	*x = SignedDepositDataMsgBody{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedDepositDataMsgBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedDepositDataMsgBody) ProtoMessage() {}

func (x *SignedDepositDataMsgBody) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedDepositDataMsgBody.ProtoReflect.Descriptor instead.
func (*SignedDepositDataMsgBody) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{7}
}

func (x *SignedDepositDataMsgBody) GetRequestID() []byte {
	if x != nil {
		return x.RequestID
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetOperatorID() uint64 {
	if x != nil {
		return x.OperatorID
	}
	return 0
}

func (x *SignedDepositDataMsgBody) GetEncryptedShare() []byte {
	if x != nil {
		return x.EncryptedShare
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetCommittee() []uint64 {
	if x != nil {
		return x.Committee
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetThreshold() uint64 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *SignedDepositDataMsgBody) GetValidatorPublicKey() []byte {
	if x != nil {
		return x.ValidatorPublicKey
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetWithdrawalCredentials() []byte {
	if x != nil {
		return x.WithdrawalCredentials
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetDepositDataSignature() []byte {
	if x != nil {
		return x.DepositDataSignature
	}
	return nil
}

func (x *SignedDepositDataMsgBody) GetOperatorSignature() []byte {
	if x != nil {
		return x.OperatorSignature
	}
	return nil
}

type ParsedSignedDepositDataMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header    *MessageHeader            `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Body      *SignedDepositDataMsgBody `protobuf:"bytes,2,opt,name=body,proto3" json:"body,omitempty"`
	Signature []byte                    `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"` // ecdsa signature
}

func (x *ParsedSignedDepositDataMessage) Reset() {
	*x = ParsedSignedDepositDataMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_types_messages_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ParsedSignedDepositDataMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ParsedSignedDepositDataMessage) ProtoMessage() {}

func (x *ParsedSignedDepositDataMessage) ProtoReflect() protoreflect.Message {
	mi := &file_types_messages_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ParsedSignedDepositDataMessage.ProtoReflect.Descriptor instead.
func (*ParsedSignedDepositDataMessage) Descriptor() ([]byte, []int) {
	return file_types_messages_proto_rawDescGZIP(), []int{8}
}

func (x *ParsedSignedDepositDataMessage) GetHeader() *MessageHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *ParsedSignedDepositDataMessage) GetBody() *SignedDepositDataMsgBody {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *ParsedSignedDepositDataMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_types_messages_proto protoreflect.FileDescriptor

var file_types_messages_proto_rawDesc = []byte{
	0x0a, 0x14, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x22, 0x7d, 0x0a, 0x0d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x6d, 0x73, 0x67, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x6d, 0x73, 0x67, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x63, 0x65,
	0x69, 0x76, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x72, 0x65, 0x63, 0x65,
	0x69, 0x76, 0x65, 0x72, 0x22, 0x71, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x34, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x91, 0x01, 0x0a, 0x04, 0x49, 0x6e, 0x69, 0x74,
	0x12, 0x20, 0x0a, 0x0b, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x44, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x04, 0x52, 0x0b, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49,
	0x44, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64,
	0x12, 0x35, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77, 0x61, 0x6c, 0x5f, 0x63,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x15, 0x77, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77, 0x61, 0x6c, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x6f, 0x72, 0x6b, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x66, 0x6f, 0x72, 0x6b, 0x22, 0x90, 0x01, 0x0a, 0x11,
	0x50, 0x61, 0x72, 0x73, 0x65, 0x64, 0x49, 0x6e, 0x69, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x34, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52,
	0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x27, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x69, 0x74, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79,
	0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xcb,
	0x01, 0x0a, 0x0d, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1c, 0x0a, 0x09, 0x54, 0x68, 0x72, 0x65, 0x73, 0x68,
	0x6f, 0x6c, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x54, 0x68, 0x72, 0x65, 0x73,
	0x68, 0x6f, 0x6c, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74, 0x65,
	0x65, 0x18, 0x03, 0x20, 0x03, 0x28, 0x04, 0x52, 0x09, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74,
	0x65, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x53, 0x68, 0x61, 0x72, 0x65, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0f, 0x53, 0x68, 0x61,
	0x72, 0x65, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x1c, 0x0a, 0x09,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x53, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x0b, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22, 0x5d, 0x0a, 0x11,
	0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x4d, 0x73, 0x67, 0x42, 0x6f, 0x64,
	0x79, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x06, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x52, 0x6f, 0x6f,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x52, 0x6f, 0x6f, 0x74, 0x12, 0x1c, 0x0a,
	0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xa3, 0x01, 0x0a, 0x17,
	0x50, 0x61, 0x72, 0x73, 0x65, 0x64, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x34, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b,
	0x67, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x34, 0x0a,
	0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x73, 0x73,
	0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x50, 0x61, 0x72, 0x74,
	0x69, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x4d, 0x73, 0x67, 0x42, 0x6f, 0x64, 0x79, 0x52, 0x04, 0x62,
	0x6f, 0x64, 0x79, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0x84, 0x03, 0x0a, 0x18, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x65, 0x70, 0x6f,
	0x73, 0x69, 0x74, 0x44, 0x61, 0x74, 0x61, 0x4d, 0x73, 0x67, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x1c,
	0x0a, 0x09, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x44, 0x12, 0x1e, 0x0a, 0x0a,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0a, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x44, 0x12, 0x26, 0x0a, 0x0e,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74, 0x65,
	0x65, 0x18, 0x04, 0x20, 0x03, 0x28, 0x04, 0x52, 0x09, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74,
	0x65, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64,
	0x12, 0x2e, 0x0a, 0x12, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x56, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79,
	0x12, 0x34, 0x0a, 0x15, 0x57, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77, 0x61, 0x6c, 0x43, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x15, 0x57, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77, 0x61, 0x6c, 0x43, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x32, 0x0a, 0x14, 0x44, 0x65, 0x70, 0x6f, 0x73, 0x69,
	0x74, 0x44, 0x61, 0x74, 0x61, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x44, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x44, 0x61, 0x74,
	0x61, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x2c, 0x0a, 0x11, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xb1, 0x01, 0x0a, 0x1e, 0x50, 0x61, 0x72,
	0x73, 0x65, 0x64, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74,
	0x44, 0x61, 0x74, 0x61, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x34, 0x0a, 0x06, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x73,
	0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x12, 0x3b, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x27, 0x2e, 0x73, 0x73, 0x76, 0x2e, 0x64, 0x6b, 0x67, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x44, 0x61, 0x74,
	0x61, 0x4d, 0x73, 0x67, 0x42, 0x6f, 0x64, 0x79, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x42, 0x27, 0x5a, 0x25,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x78, 0x61,
	0x70, 0x70, 0x2f, 0x73, 0x73, 0x76, 0x2d, 0x73, 0x70, 0x65, 0x63, 0x2f, 0x64, 0x6b, 0x67, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_types_messages_proto_rawDescOnce sync.Once
	file_types_messages_proto_rawDescData = file_types_messages_proto_rawDesc
)

func file_types_messages_proto_rawDescGZIP() []byte {
	file_types_messages_proto_rawDescOnce.Do(func() {
		file_types_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_types_messages_proto_rawDescData)
	})
	return file_types_messages_proto_rawDescData
}

var file_types_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_types_messages_proto_goTypes = []interface{}{
	(*MessageHeader)(nil),                  // 0: ssv.dkg.types.MessageHeader
	(*Message)(nil),                        // 1: ssv.dkg.types.Message
	(*Init)(nil),                           // 2: ssv.dkg.types.Init
	(*ParsedInitMessage)(nil),              // 3: ssv.dkg.types.ParsedInitMessage
	(*LocalKeyShare)(nil),                  // 4: ssv.dkg.types.LocalKeyShare
	(*PartialSigMsgBody)(nil),              // 5: ssv.dkg.types.PartialSigMsgBody
	(*ParsedPartialSigMessage)(nil),        // 6: ssv.dkg.types.ParsedPartialSigMessage
	(*SignedDepositDataMsgBody)(nil),       // 7: ssv.dkg.types.SignedDepositDataMsgBody
	(*ParsedSignedDepositDataMessage)(nil), // 8: ssv.dkg.types.ParsedSignedDepositDataMessage
}
var file_types_messages_proto_depIdxs = []int32{
	0, // 0: ssv.dkg.types.Message.header:type_name -> ssv.dkg.types.MessageHeader
	0, // 1: ssv.dkg.types.ParsedInitMessage.header:type_name -> ssv.dkg.types.MessageHeader
	2, // 2: ssv.dkg.types.ParsedInitMessage.body:type_name -> ssv.dkg.types.Init
	0, // 3: ssv.dkg.types.ParsedPartialSigMessage.header:type_name -> ssv.dkg.types.MessageHeader
	5, // 4: ssv.dkg.types.ParsedPartialSigMessage.body:type_name -> ssv.dkg.types.PartialSigMsgBody
	0, // 5: ssv.dkg.types.ParsedSignedDepositDataMessage.header:type_name -> ssv.dkg.types.MessageHeader
	7, // 6: ssv.dkg.types.ParsedSignedDepositDataMessage.body:type_name -> ssv.dkg.types.SignedDepositDataMsgBody
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_types_messages_proto_init() }
func file_types_messages_proto_init() {
	if File_types_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_types_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MessageHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Init); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ParsedInitMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LocalKeyShare); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PartialSigMsgBody); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ParsedPartialSigMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedDepositDataMsgBody); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_types_messages_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ParsedSignedDepositDataMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_types_messages_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_types_messages_proto_goTypes,
		DependencyIndexes: file_types_messages_proto_depIdxs,
		MessageInfos:      file_types_messages_proto_msgTypes,
	}.Build()
	File_types_messages_proto = out.File
	file_types_messages_proto_rawDesc = nil
	file_types_messages_proto_goTypes = nil
	file_types_messages_proto_depIdxs = nil
}
