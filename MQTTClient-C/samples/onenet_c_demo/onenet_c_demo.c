/*******************************************************************************
 * Copyright (c) 2012, 2016 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution. 
 *
 * The Eclipse Public License is available at 
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Ian Craggs - initial contribution
 *    Ian Craggs - change delimiter option from char to string
 *    Al Stockdill-Mander - Version using the embedded C client
 *    Ian Craggs - update MQTTClient function names
 *******************************************************************************/

#include <stdio.h>

#include <signal.h>
#include <memory.h>
#include <sys/time.h>
#include <stdint.h>
#include "MQTTClient.h"

#define PRODUCT_ID					"371774"
#define DEVICE_NAME			"tttt"
#define DEVICE_SECRET       "o9cG6c1UNIyE6L2d1Bt+MSqcb16rJMvPZbixVi11qGc="

//const char *base_subscribe_topic = "$sys/%s/%s/#";
//const char *base_dp_upload_topic = "$sys/%s/%s/dp/post/json";
const char *base_cmd_response_topic = "$sys/%s/%s/cmd/response/%s";

const char* base_dp_str = "{"
                          "\"id\":%d,"
                          "\"dp\": {"
                          "\"color\":"
                          "[ {"
                          "\"v\": %d"
                          "}"
                          "]"
                          "}"
                          "}";

volatile int toStop = 0;

void cfinish(int sig)
{
	signal(SIGINT, NULL);
	toStop = 1;
}

void messageArrived(MessageData* md)
{
	MQTTMessage* message = md->message;

	printf("Packet Ident    ：%d\n", message->id);
	printf("Topic   : %d\t", md->topicName->lenstring.len);
	printf("%s\n", md->topicName->lenstring.data);
	printf("Payload : %d\t", (int)message->payloadlen);
	printf("%s\n", (char*)message->payload);
	printf("Qos             : %d\n", message->qos);
	printf("\n");
}

/* main function */
int main(int argc, char** argv)
{
	int rc = 0;

	/* setup the buffer, it must big enough for aliyun IoT platform */
	unsigned char buf[1000];
	unsigned char readbuf[1000];

	Network n;
	MQTTClient c;
	char *host = "183.230.40.96";
	short port = 1883;

	const char *subTopic = "$sys/"PRODUCT_ID"/"DEVICE_NAME"/#";
	const char *pubTopic = "$sys/"PRODUCT_ID"/"DEVICE_NAME"/dp/post/json";

	/* invoke aiotMqttSign to generate mqtt connect parameters */
	char clientId[150] = {0};
	char username[65] = {0};
	char password[200] = {0};
	char payload[512] = {'\0'};

	if (rc = onenetMqttSign("2018-10-31", (char *)PRODUCT_ID, 4102444800, (char *)DEVICE_SECRET, DEVICE_NAME, password, sizeof(password))) {
		return -1;
	}

	memcpy(clientId, "tttt", strlen("tttt"));
	memcpy(username, "371774", strlen("371774"));
	//memcpy(password, "version=2018-10-31&res=products%2F371774%2Fdevices%2Ftttt&et=2524608000&method=sha1&sign=FByE209L%2BUv3J059NJ0YCFdVOXU%3D",
	//	 strlen("version=2018-10-31&res=products%2F371774%2Fdevices%2Ftttt&et=2524608000&method=sha1&sign=FByE209L%2BUv3J059NJ0YCFdVOXU%3D"));
	printf("clientid: %s\n", clientId);
	printf("username: %s\n", username);
	printf("password: %s\n", password);

	signal(SIGINT, cfinish);
	signal(SIGTERM, cfinish);

	/* network init and establish network to aliyun IoT platform */
	NetworkInit(&n);
	rc = NetworkConnect(&n, host, port);
	printf("NetworkConnect %d\n", rc);

	/* init mqtt client */
	MQTTClientInit(&c, &n, 1000, buf, sizeof(buf), readbuf, sizeof(readbuf));

	/* set the default message handler */
	c.defaultMessageHandler = messageArrived;

	/* set mqtt connect parameter */
	MQTTPacket_connectData data = MQTTPacket_connectData_initializer;       
	data.willFlag = 0;
	data.MQTTVersion = 4;
	data.clientID.cstring = clientId;
	data.username.cstring = username;
	data.password.cstring = password;
	data.keepAliveInterval = 60;
	data.cleansession = 1;
	printf("Connecting to %s %d\n", host, port);

	rc = MQTTConnect(&c, &data);
	printf("MQTTConnect %d, Connect aliyun IoT Cloud Success!\n", rc);
    
    printf("Subscribing to %s\n", subTopic);
	rc = MQTTSubscribe(&c, subTopic, 1, messageArrived);
	printf("MQTTSubscribe %d\n", rc);

	int cnt = 0;
    unsigned int msgid = 0;
    int rand_dp_id = 0;
    int rand_value = 0;
	int iii;
	while (!toStop)
	{
		MQTTYield(&c, 1000);	

		if (++cnt % 5 == 0) {
		    //assemble payload
		    srand(time(NULL));
			rand_dp_id = rand() % 10;
			rand_value = rand() % 10000;
	
			snprintf(payload,sizeof(payload),base_dp_str,rand_dp_id,rand_value);
			printf("payload:%s\n", payload);
			MQTTMessage msg = {
				QOS1, 
				0,
				0,
				0,
				payload,
				strlen(payload),
			};
            msg.id = ++msgid;
			rc = MQTTPublish(&c, pubTopic, &msg);
			printf("MQTTPublish %d, msgid %d\n", rc, msgid);
		}
	}

	printf("Stopping\n");

	MQTTDisconnect(&c);
	NetworkDisconnect(&n);

	return 0;
}
