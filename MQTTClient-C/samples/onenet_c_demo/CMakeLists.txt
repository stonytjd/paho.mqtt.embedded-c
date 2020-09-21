#*******************************************************************************
#  Copyright (c) 2017 IBM Corp.
#
#  All rights reserved. This program and the accompanying materials
#  are made available under the terms of the Eclipse Public License v1.0
#  and Eclipse Distribution License v1.0 which accompany this distribution.
#
#  The Eclipse Public License is available at
#     http://www.eclipse.org/legal/epl-v10.html
#  and the Eclipse Distribution License is available at
#    http://www.eclipse.org/org/documents/edl-v10.php.
#
#  Contributors:
#     Ian Craggs - initial version
#*******************************************************************************/


add_executable(
  onenet_c_demo
  hmac_sha1.c
  base64.c
  onenet_c_demo.c
  onenet_mqtt_sign.c
)
target_link_libraries(onenet_c_demo paho-embed-mqtt3cc paho-embed-mqtt3c)
target_include_directories(onenet_c_demo PRIVATE "../../src" "../../src/linux")
target_compile_definitions(onenet_c_demo PRIVATE MQTTCLIENT_PLATFORM_HEADER=MQTTLinux.h)
