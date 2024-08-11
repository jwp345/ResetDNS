# 유해 사이트 차단 프로젝트

### 목표
> 유해사이트 차단을 위해 패킷의 DNS 목적지를 확인하여 목적지를 확인 후 원하는 IP로 리다이렉트 혹은 차단

### 1. 첫번째 아이디어
> DNS 응답을 추출한 후 TCP의 RST 플래그를 활용하여 클라이언트의 요청을 거부
+ 왜 TCP인가? wireshark 툴로 패킷을 분석해본 결과 브라우저(chrome)의 DNS 쿼리 요청이 TCP와 HTTP(S)를 사용한 DNS 질의를 하는 것을 확인
+ 시도: DNS(53번 포트)로 요청하는 네트워크 패킷을 가로챈 뒤, 도메인 부분을 추출하여 타깃 도메인이면 RST 플래그가 담긴 네트워크 패킷으로 요청을 거부
+ 직면한 문제들
  1. DNS 요청이 바로 처리되지 않고, 일정 버퍼 크기만큼 쌓아둔 후에 보내지는 문제
  2. RST 패킷이 Wireshark에서는 정상적으로 전송된 것으로 보이지만, 실제로는 연결이 종료되지 않는 문제
  3. RST 패킷을 성공적으로 전송하여 연결이 종료된 것처럼 보였으나, 브라우저에서 페이지가 정상적으로 로딩되는 문제
+ 해결
  1. pcap_open_live()와 pcap_loop() 메서드는 일정 시간 동안 버퍼를 모아두고 처리합니다. 이를 pcap_create()와 pcap_set_immediate_mode()를 사용해 패킷이 들어오는 즉시 처리하도록 변경했습니다.
  2. 방화벽이 켜져 있는 경우, Windows에서 RST 패킷 전송이 막혀 Wireshark에는 보이지만 정상적으로 발송되지 않았음을 발견했습니다.
  3. Chrome 내부 브라우저 로그 확인(chrome://net-internals/?#events)으로 문제를 더 정확히 파악할 수 있었습니다.

+ 결과
![rst 패킷 후처리](https://github.com/user-attachments/assets/253ea5f7-2d9f-438e-9535-2503da1216d0)
![커넥션 실패 후 호스트 리졸버 호출](https://github.com/user-attachments/assets/ec75ea69-070d-441d-8d64-157ca52121a9)
+ 알게된 사실
  1. RST 패킷의 SEQ에 이전 패킷의 ACK를 담아야 강제 종료로 인식됩니다.
  2. Wireshark는 일반적으로 네트워크 인터페이스 레벨에서 패킷을 캡처합니다. 이는 운영 체제의 네트워크 스택에서 패킷이 생성된 직후, 방화벽 처리 이전 단계일 수 있습니다.
  3. DNS를 TCP를 사용한 HTTPS나 HTTP프로토콜 등을 사용하는 요청은 브라우저의 주도로 이뤄집니다.
  4. Chrome 브라우저 내에는 HOST Resolver라는 기능이 있으며, 이는 DNS를 캐시하고 DOH(DNS over HTTPS) 프로토콜을 통해 안정적으로 DNS를 가져오는 역할을 하는 것으로 추정됩니다.
    <br>[추정 근거 출처](https://blog.chromium.org/2020/05/a-safer-and-more-private-browsing-DoH.html)
<hr/>

 ### 2. 두번째 아이디어
> DNS 응답을 추출한 후 UDP DNS Response 응답을 만들어 DNS 서버보다 빨리 보내어 원하는 ip주소로 리다이렉트
+ 시도: DNS 캐시를 비우고(chrome://net-internals/#dns에서 DNS 캐시 비우기 및 ipconfig/flushdns 명령어 사용), 브라우저가 UDP로 DNS 질의 응답을 가져오게 한 후, 조작된 UDP DNS 응답을 먼저 보내 특정 IP로 리다이렉트하려 했습니다.
+ 직면했던 문제들
  1. 브라우저가 먼저 비슷한 DNS 응답 메시지를 발행해도 후속 메시지만 인식하는 문제(Wireshark에서는 위조 패킷을 정상으로 인식)
     ![dns response 무엇이 다를까](https://github.com/user-attachments/assets/be6d255b-76c5-488d-b9ad-bba6528f6f2e)
     ![wireshark에선 먼저 온 패킷을 정상 패킷으로 인정](https://github.com/user-attachments/assets/f4fe8c32-e38f-4b5d-a35a-d935ef95fe56)
  2. nslookup 같은 Windows 기본 DNS 조회 명령어도 위조 패킷을 인정하지 않는 문제<br>
     ![nslookup 결과](https://github.com/user-attachments/assets/972e8eca-0c93-4a3a-9454-4f47b116d48d)

+ 원인 파악
  1. IP 헤더의 identification 값이 다르다는 것을 발견했습니다(특별한 ID 생성 방식이 있는지 검증 필요)
  2. Windows DNS Resolver(nslookup)로 조회할 때 A 레코드 및 AAAA 레코드(IPv6)를 함께 조회하는 것을 확인했습니다. 하지만 IPv6를 함께 조회하는 것이 의미가 있을지 의문입니다.
 <br>![dig + delv 결과](https://github.com/user-attachments/assets/e5b67595-88b7-41b4-bbb2-c97ec6bee72d) 
  3. dig +dnssec 검증 및 delv 검증 시 통과하지 못했습니다(DNSSEC 필드도 고려해야 할지 고민 중)

+ 추후 방향
  + 비슷한 시도를 한 사례들을 찾을 수 있었는데, Stack Overflow나 Superuser 같은 커뮤니티의 답변을 보면, 이러한 접근 방식은 기본적으로 검증이 어렵다고 합니다. 특히 DNSSEC 필드와 관련이 있을 것으로 추정되지만, 브라우저가 요청하는 일부 사이트는 A 레코드만으로도 충분하기 때문에 다른 방법도 고려해볼 필요가 있습니다.
+ 결론
  + 제가 생각보다 더 모르는 부분이 많다는 것을 깨달았습니다. Windows와 브라우저의 Host(DNS) Resolver는 단순한 캐시 이상의 역할을 하며, 여러 공격을 어렵게 하기 위해 고안된 것 같습니다. 시간이 날 때 DNS 처리나 UDP 관련 새로운 정보를 접하게 되면 다시 도전해볼 예정입니다.
 <br>

[프로젝트 아이디어 출처 - 인프런 널널한 개발자님의 이해하면 인생이 바뀌는 네트워크 프로그래밍](https://www.inflearn.com/course/%EC%9D%B4%ED%95%B4%ED%95%98%EB%A9%B4-%EC%9D%B8%EC%83%9D%EC%9D%B4-%EB%B0%94%EB%80%8C%EB%8A%94-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D)
