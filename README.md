# 유해 사이트 차단 프로젝트

### 목표
> 유해사이트 차단을 위해 패킷의 DNS 목적지를 확인하여 목적지를 확인 후 원하는 IP로 리다이렉트 혹은 차단

### 1. 첫번째 아이디어
> DNS 응답을 추출한 후 TCP의 RST 플래그를 활용하여 클라이언트의 요청을 거부하게 하자!
+ 의문점: DNS 요청은 UDP라고 보통 알려져 있는데 왜 TCP에서 요청을 추출하고 막는가? wireshark 툴로 패킷을 분석해본 결과 브라우저의 DNS 쿼리 요청은 주로 TCP를 사용한 DNS 질의를 하고 있었기에 이 방향으로 결정
+ 의도: DNS(53번 포트)로 요청하는 네트워크 패킷을 가로챈 뒤, 도메인 부분을 추출하여 타깃 도메인이면 RST 플래그가 담긴 네트워크 패킷으로 요청을 거부하도록 시도
+ 직면했던 문제들
  1. DNS 요청들에 대한 처리가 바로바로 이뤄지는 것이 아닌 일정 버퍼 크기만큼 쌓아뒀다 보내는 문제
  2. RST 패킷을 정상적으로 전송하였다고 wireshark에서도 그렇게 보이지만 실제로는 RST 플래그가 담긴 패킷이 안보내졌는지 연결이 종료되지 않음
  3. RST 패킷을 성공적으로 보내고 연결이 종료된것으로 인식하여 DNS 서버에 RST 플래그가 담긴 플래그로 응답함에도, 브라우저에서 페이지를 정상적으로 로딩하여 의도한대로 동작하지 않았음
+ 해결
  1. pcap_open_live() 와 pcap_loop() 메소드는 일정시간 버퍼를 모아뒀다가 처리하는 형식이었음 이를 pcap_create()와 pcap_set_immediate_mode()를 활용하여 패킷이 들어오는 즉시 처리하도록 변경
  2. 방화벽이 켜져있는 경우, 윈도우에서 RST 패킷을 전송하는 것을 막아놓아 wireshark에선 보이지만 정상적으로 발송이 안됐었음
  3. 크롬 내부 브라우저 로그 확인(chrome://net-internals/?#events)

+ 결과
![rst 패킷 후처리](https://github.com/user-attachments/assets/82a1d71f-cbb6-4e7d-9280-4448e99b64ab)
![커넥션 실패 후 호스트 리졸버 호출](https://github.com/user-attachments/assets/ec75ea69-070d-441d-8d64-157ca52121a9)
+ 알게된 사실
  1. RST 패킷의 SEQ에 이전 패킷의 ack를 담아야 강제 종료로 인식한다.
  2. Wireshark는 일반적으로 네트워크 인터페이스 레벨에서 패킷을 캡처합니다. 이는 운영 체제의 네트워크 스택에서 패킷이 생성된 직후, 방화벽 처리 이전 단계일 수 있습니다.
  3. DNS를 TCP를 사용한 HTTPS나 HTTP프로토콜 등을 사용하는 요청은 브라우저가 요청하는 것이다.
  4. 크롬 브라우저 안에는 HOST Resolver란 것이 있으며, 어떠한 일들을 하는지 명확하게 설명해놓은 문서는 없지만, DNS를 캐시해놓으며 DOH(DNS over HTTPS)같은 프로토콜을 통해 DNS를 안정적으로 가져오는 역할을 하는것으로 추정된다.
     [출처](https://blog.chromium.org/2020/05/a-safer-and-more-private-browsing-DoH.html)
<hr/>

 ### 2. 두번째 아이디어
> DNS 응답을 추출한 후 UDP DNS Response 응답을 만들어 DNS 서버보다 빨리 보내어 원하는 ip주소로 리다이렉트 시키자
+ 의도: 기본적으로 DNS 캐시를 chrome://net-internals/#dns에서 dns캐시를 비우고 ipconfig/flushdns 명령어로 로컬의 캐시를 지워놓으면 DNS 질의 응답을 UDP로 가져온다. 따라서, UDP DNS Response 패킷을 먼저 보내어 DNS 응답을 조작해 특정ip로 리다이렉트 시키게끔 한다
+ 
 <br>
[프로젝트 아이디어 출처 - 널널한 개발자님의 이해하면 인생이 바뀌는 프로그래밍](https://www.inflearn.com/course/%EC%9D%B4%ED%95%B4%ED%95%98%EB%A9%B4-%EC%9D%B8%EC%83%9D%EC%9D%B4-%EB%B0%94%EB%80%8C%EB%8A%94-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D)
