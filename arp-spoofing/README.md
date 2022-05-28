# ARP Spoofing Tool
```
syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]
```

## 각 함수 설명
`void *arp_spoofing_reply(void* dev)`: 5초 마다 sender와 target에 arp reply를 통해, ARP table을 업데이트한다.

`void *arp_spoofing_reply(void* dev)`: 모든 패킷을 확인하여, sender->attacker로 unicast ARP 질의가 온 상황이라면, 적절하게 ARP table을 업데이트한다.

`void *arp_spoofing_relay(void* dev)`: 모든 패킷을 확인하여, sender->attacker로 relay된 패킷을 gateway로 돌려서, 패킷이 외부로 전달되도록 한다. 반대로, target->attafcker로 relay된 패킷을 sender에게 돌려서, 외부 패킷이 sender에게 전달되도록 한다.



## 주의할 점
1. 스레드마다 서로 다른 `pcap *handle`을 사용하여야, 각 스레드에서 순차적으로 해당하는 네트워크 인터페이스에 대한 패킷을 잡아먹을 수 있다.
2. gateway의 ARP Cache Table을 오염시켜야, victim의 응답으로 오는 패킷도 받을 수 있다.
3. ARP Cache를 일정 시간 뒤에 업데이트하기 전에, victim은 attacker에게 unicast로 질의를 한다. 따라서, 이러한 패킷이 전달되었을 때, '내가 gateway에요!'라는 답장을 주어야 한다.