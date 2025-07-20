package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// MockClient implements the Client interface for testing
type MockClient struct {
	mock.Mock
}

func (m *MockClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*packet.Packet), args.Error(1)
}

func (m *MockClient) SendRequestWithRetry(ctx context.Context, req *packet.Packet, maxRetries int) (*packet.Packet, error) {
	args := m.Called(ctx, req, maxRetries)
	return args.Get(0).(*packet.Packet), args.Error(1)
}

func (m *MockClient) GetStatistics() *Statistics {
	args := m.Called()
	return args.Get(0).(*Statistics)
}

func (m *MockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewHighLevelClient(t *testing.T) {
	mockClient := &MockClient{}
	logger := log.NewDefaultLogger()

	hlc := NewHighLevelClient(mockClient, logger)

	assert.NotNil(t, hlc)
	assert.Equal(t, mockClient, hlc.client)
	assert.Equal(t, logger, hlc.logger)
}

func TestNewHighLevelClientWithNilLogger(t *testing.T) {
	mockClient := &MockClient{}

	hlc := NewHighLevelClient(mockClient, nil)

	assert.NotNil(t, hlc)
	assert.NotNil(t, hlc.logger)
}

func TestRequestBuilder_BasicRequest(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Create a mock response
	response := packet.New(packet.CodeAccessAccept, 1)
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response, nil)

	// Build and send request
	resp, err := hlc.NewRequest(packet.CodeAccessRequest).
		WithUserName("testuser").
		WithPassword("testpass").
		Send(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeAccessAccept, resp.Code)

	mockClient.AssertExpectations(t)
}

func TestRequestBuilder_WithAttributes(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	response := packet.New(packet.CodeAccessAccept, 1)
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 5).Return(response, nil)

	// Test various attribute types
	resp, err := hlc.NewRequest(packet.CodeAccessRequest).
		WithUserName("testuser").
		WithPassword("testpass").
		WithNASIPAddress("192.168.1.1").
		WithNASPort(1000).
		WithCallingStationID("01-23-45-67-89-ab").
		WithCalledStationID("00-11-22-33-44-55").
		WithNASIdentifier("nas01").
		WithRetries(5).
		WithTimeout(10 * time.Second).
		Send(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	mockClient.AssertExpectations(t)
}

func TestRequestBuilder_WithAttributeTypes(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Test different attribute value types
	builder := hlc.NewRequest(packet.CodeAccessRequest)

	// Test string attribute
	builder.WithStringAttribute(packet.AttrUserName, "testuser")
	assert.Len(t, builder.packet.Attributes, 1)
	assert.Equal(t, []byte("testuser"), builder.packet.Attributes[0].Value)

	// Test integer attribute
	builder.WithIntegerAttribute(packet.AttrNASPort, 1000)
	assert.Len(t, builder.packet.Attributes, 2)
	assert.Equal(t, packet.EncodeUint32(1000), builder.packet.Attributes[1].Value)

	// Test IP attribute
	builder.WithIPAttribute(packet.AttrNASIPAddress, "192.168.1.1")
	assert.Len(t, builder.packet.Attributes, 3)
	assert.Equal(t, packet.EncodeIPAddress("192.168.1.1"), builder.packet.Attributes[2].Value)
}

func TestRequestBuilder_WithGenericAttribute(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	builder := hlc.NewRequest(packet.CodeAccessRequest)

	// Test with string
	builder.WithAttribute(packet.AttrUserName, "testuser")
	assert.Equal(t, []byte("testuser"), builder.packet.Attributes[0].Value)

	// Test with []byte
	builder.WithAttribute(packet.AttrUserPassword, []byte("password"))
	assert.Equal(t, []byte("password"), builder.packet.Attributes[1].Value)

	// Test with uint32
	builder.WithAttribute(packet.AttrNASPort, uint32(1000))
	assert.Equal(t, packet.EncodeUint32(1000), builder.packet.Attributes[2].Value)

	// Test with int
	builder.WithAttribute(packet.AttrSessionTimeout, int(3600))
	assert.Equal(t, packet.EncodeUint32(3600), builder.packet.Attributes[3].Value)

	// Test with time.Time
	testTime := time.Now()
	builder.WithAttribute(55, testTime) // EventTimestamp
	assert.Equal(t, packet.EncodeTime(testTime), builder.packet.Attributes[4].Value)

	// Test with int type (should convert to uint32 and encode)
	builder.WithAttribute(packet.AttrCallingStationID, 123456)
	assert.Equal(t, packet.EncodeUint32(123456), builder.packet.Attributes[5].Value)
}

func TestResponseHelper_IsSuccess(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Test success response
	successResponse := packet.New(packet.CodeAccessAccept, 1)
	helper := hlc.NewResponseHelper(successResponse)
	assert.True(t, helper.IsSuccess())
	assert.False(t, helper.IsFailure())
	assert.False(t, helper.IsChallenge())

	// Test failure response
	failureResponse := packet.New(packet.CodeAccessReject, 1)
	helper = hlc.NewResponseHelper(failureResponse)
	assert.False(t, helper.IsSuccess())
	assert.True(t, helper.IsFailure())
	assert.False(t, helper.IsChallenge())

	// Test challenge response
	challengeResponse := packet.New(packet.CodeAccessChallenge, 1)
	helper = hlc.NewResponseHelper(challengeResponse)
	assert.False(t, helper.IsSuccess())
	assert.False(t, helper.IsFailure())
	assert.True(t, helper.IsChallenge())
}

func TestResponseHelper_GetAttributes(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Create response with various attributes
	response := packet.New(packet.CodeAccessAccept, 1)
	response.Attributes = []packet.Attribute{
		{Type: packet.AttrReplyMessage, Value: []byte("Welcome")},
		{Type: packet.AttrFramedIPAddress, Value: packet.EncodeIPAddress("10.0.0.1")},
		{Type: packet.AttrSessionTimeout, Value: packet.EncodeUint32(3600)},
		{Type: packet.AttrFramedIPNetmask, Value: packet.EncodeIPAddress("255.255.255.0")},
		{Type: packet.AttrIdleTimeout, Value: packet.EncodeUint32(1800)},
	}

	helper := hlc.NewResponseHelper(response)

	// Test string attribute
	message, found := helper.GetReplyMessage()
	assert.True(t, found)
	assert.Equal(t, "Welcome", message)

	// Test IP attribute
	ip, found := helper.GetFramedIPAddress()
	assert.True(t, found)
	assert.Equal(t, "10.0.0.1", ip)

	// Test integer attribute
	timeout, found := helper.GetSessionTimeout()
	assert.True(t, found)
	assert.Equal(t, uint32(3600), timeout)

	// Test netmask
	netmask, found := helper.GetFramedNetmask()
	assert.True(t, found)
	assert.Equal(t, "255.255.255.0", netmask)

	// Test idle timeout
	idle, found := helper.GetIdleTimeout()
	assert.True(t, found)
	assert.Equal(t, uint32(1800), idle)

	// Test non-existent attribute
	_, found = helper.GetStringAttribute(packet.AttrUserName)
	assert.False(t, found)
}

func TestResponseHelper_GetAllAttributes(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	response := packet.New(packet.CodeAccessAccept, 1)
	response.Attributes = []packet.Attribute{
		{Type: packet.AttrReplyMessage, Value: []byte("Test1")},
		{Type: packet.AttrReplyMessage, Value: []byte("Test2")},
		{Type: packet.AttrFramedIPAddress, Value: packet.EncodeIPAddress("10.0.0.1")},
	}

	helper := hlc.NewResponseHelper(response)

	// Test get all attributes
	allAttrs := helper.GetAllAttributes()
	assert.Len(t, allAttrs, 3)

	// Test get attributes by type
	replyMessages := helper.GetAttributesByType(packet.AttrReplyMessage)
	assert.Len(t, replyMessages, 2)
	assert.Equal(t, []byte("Test1"), replyMessages[0].Value)
	assert.Equal(t, []byte("Test2"), replyMessages[1].Value)

	// Test get attributes by type (single)
	ipAttrs := helper.GetAttributesByType(packet.AttrFramedIPAddress)
	assert.Len(t, ipAttrs, 1)
	assert.Equal(t, packet.EncodeIPAddress("10.0.0.1"), ipAttrs[0].Value)

	// Test get attributes by type (non-existent)
	userAttrs := helper.GetAttributesByType(packet.AttrUserName)
	assert.Len(t, userAttrs, 0)
}

func TestBatchRequest_EmptyBatch(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	batch := hlc.NewBatchRequest()
	response, err := batch.Send(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, 0, response.Success)
	assert.Equal(t, 0, response.Failed)
	assert.Empty(t, response.Responses)
	assert.Empty(t, response.Errors)
}

func TestBatchRequest_SuccessfulBatch(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Mock successful responses
	response1 := packet.New(packet.CodeAccessAccept, 1)
	response2 := packet.New(packet.CodeAccessAccept, 2)

	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response1, nil).Once()
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response2, nil).Once()

	// Create batch request
	batch := hlc.NewBatchRequest().
		Add(hlc.NewRequest(packet.CodeAccessRequest).WithUserName("user1")).
		Add(hlc.NewRequest(packet.CodeAccessRequest).WithUserName("user2")).
		WithTimeout(10 * time.Second)

	batchResponse, err := batch.Send(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, batchResponse)
	assert.Equal(t, 2, batchResponse.Success)
	assert.Equal(t, 0, batchResponse.Failed)
	assert.Len(t, batchResponse.Responses, 2)
	assert.Len(t, batchResponse.Errors, 2)
	assert.Nil(t, batchResponse.Errors[0])
	assert.Nil(t, batchResponse.Errors[1])

	mockClient.AssertExpectations(t)
}

func TestBatchRequest_WithErrors(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Mock one successful and one error response
	response1 := packet.New(packet.CodeAccessAccept, 1)

	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response1, nil).Once()
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return((*packet.Packet)(nil), assert.AnError).Once()

	// Create batch request
	batch := hlc.NewBatchRequest().
		Add(hlc.NewRequest(packet.CodeAccessRequest).WithUserName("user1")).
		Add(hlc.NewRequest(packet.CodeAccessRequest).WithUserName("user2"))

	batchResponse, err := batch.Send(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, batchResponse)
	assert.Equal(t, 1, batchResponse.Success)
	assert.Equal(t, 1, batchResponse.Failed)
	assert.Len(t, batchResponse.Responses, 2)
	assert.Len(t, batchResponse.Errors, 2)
	// Check that we have exactly one error and one nil
	errorCount := 0
	nilCount := 0
	for _, err := range batchResponse.Errors {
		if err != nil {
			errorCount++
		} else {
			nilCount++
		}
	}
	assert.Equal(t, 1, errorCount, "Should have exactly 1 error")
	assert.Equal(t, 1, nilCount, "Should have exactly 1 nil error")

	mockClient.AssertExpectations(t)
}

func TestHighLevelClient_GetClient(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	assert.Equal(t, mockClient, hlc.GetClient())
}

func TestHighLevelClient_GetStatistics(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	stats := &Statistics{
		RequestsSent: 100,
		Errors:       5,
	}

	mockClient.On("GetStatistics").Return(stats)

	result := hlc.GetStatistics()
	assert.Equal(t, stats, result)

	mockClient.AssertExpectations(t)
}

func TestHighLevelClient_Close(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	mockClient.On("Close").Return(nil)

	err := hlc.Close()
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestRequestBuilder_Timeout(t *testing.T) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	// Create a context that will timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Make the mock take longer than the timeout
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return((*packet.Packet)(nil), context.DeadlineExceeded)

	time.Sleep(2 * time.Millisecond) // Ensure timeout

	_, err := hlc.NewRequest(packet.CodeAccessRequest).
		WithUserName("testuser").
		Send(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// Benchmark tests
func BenchmarkRequestBuilder_BuildAndSend(b *testing.B) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	response := packet.New(packet.CodeAccessAccept, 1)
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hlc.NewRequest(packet.CodeAccessRequest).
			WithUserName("testuser").
			WithPassword("testpass").
			WithNASIPAddress("192.168.1.1").
			WithNASPort(1000).
			Send(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchRequest_MultipleRequests(b *testing.B) {
	mockClient := &MockClient{}
	hlc := NewHighLevelClient(mockClient, nil)

	response := packet.New(packet.CodeAccessAccept, 1)
	mockClient.On("SendRequestWithRetry", mock.Anything, mock.Anything, 3).Return(response, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := hlc.NewBatchRequest()
		for j := 0; j < 10; j++ {
			batch.Add(hlc.NewRequest(packet.CodeAccessRequest).WithUserName("user"))
		}
		_, err := batch.Send(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
}
