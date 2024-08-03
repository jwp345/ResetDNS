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
![rst 패킷 후처리](https://github.com/user-attachments/assets/253ea5f7-2d9f-438e-9535-2503da1216d0)
![커넥션 실패 후 호스트 리졸버 호출](https://github.com/user-attachments/assets/ec75ea69-070d-441d-8d64-157ca52121a9)
+ 알게된 사실
  1. RST 패킷의 SEQ에 이전 패킷의 ack를 담아야 강제 종료로 인식한다.
  2. Wireshark는 일반적으로 네트워크 인터페이스 레벨에서 패킷을 캡처합니다. 이는 운영 체제의 네트워크 스택에서 패킷이 생성된 직후, 방화벽 처리 이전 단계일 수 있습니다.
  3. DNS를 TCP를 사용한 HTTPS나 HTTP프로토콜 등을 사용하는 요청은 브라우저가 요청하는 것이다.
  4. 크롬 브라우저 안에는 HOST Resolver란 것이 있으며, 어떠한 일들을 하는지 명확하게 설명해놓은 문서는 없지만, DNS를 캐시해놓으며 DOH(DNS over HTTPS)같은 프로토콜을 통해 DNS를 안정적으로 가져오는 역할을 하는것으로 추정된다.
    <br>[추정 근거 출처](https://blog.chromium.org/2020/05/a-safer-and-more-private-browsing-DoH.html)
<hr/>

 ### 2. 두번째 아이디어
> DNS 응답을 추출한 후 UDP DNS Response 응답을 만들어 DNS 서버보다 빨리 보내어 원하는 ip주소로 리다이렉트 시키자
+ 의도: 기본적으로 DNS 캐시를 chrome://net-internals/#dns에서 dns캐시를 비우고 ipconfig/flushdns 명령어로 로컬의 캐시를 지워놓으면 DNS 질의 응답을 UDP로 가져온다. 따라서, UDP DNS Response 패킷을 먼저 보내어 DNS 응답을 조작해 특정ip로 리다이렉트 시키게끔 한다
+ 직면했던 문제들
  1. 브라우저에선 비슷한 DNS Response 메시지를 먼저 발행했음에도, 후속 메시지만 인식하는 문제(wireshark에선 위조 패킷을 정상으로 인식)
     ![dns response 무엇이 다를까](https://github.com/user-attachments/assets/be6d255b-76c5-488d-b9ad-bba6528f6f2e)
     ![wireshark에선 먼저 온 패킷을 정상 패킷으로 인정](https://github.com/user-attachments/assets/f4fe8c32-e38f-4b5d-a35a-d935ef95fe56)
  2. nslookup과 같은 window의 기본 dns 조회 명령어도 위조 패킷을 인정 안함<br>
     ![nslookup 결과](https://github.com/user-attachments/assets/972e8eca-0c93-4a3a-9454-4f47b116d48d)

+ 원인 파악
  1. ip 헤더의 identification값이 다름(특별한 id 생성 방식이 있고 검증하나?), dig +dnssec 검증, delv 검증 시 통과를 못함(dnssec 필드도 고려해서 짜야하나..?)
<br>![dig + delv 결과](https://github.com/user-attachments/assets/e5b67595-88b7-41b4-bbb2-c97ec6bee72d) 
  
  2. Windwos DNS Resolver(nslookup)으로 dns 조회 명령 시 A레코드 및 AAAA레코드(ipv6)를 같이 조회하는 걸 발견(그러나 ipv6 같이 조회하는 게 의미가 있을지..?)

+ 추후 방향
  > 인터넷을 찾아보니 나와 비슷한 시도를 한 사례들이 종종 보이는데 stackoverflow, superuser등의 커뮤니티 답변을 보면 왜 그런 짓을 하냐, ISP 같은 곳 온 요청인지 기본적으로 검증을 한다는데..<br>
  그게 DNSSEC 필드 등과 같은 것과 연관이 있는지 모르겠다..(그러나 브라우저에 DNS 요청을 할 때 A레코드까지만 있어도 되는 사이트가 있는 곳은 상관없어야 하는 것 아닌가?)
+ 결론
  + 생각보다 나는 더 무지하다.. 윈도우와 브라우저의 Host(DNS) Resolver는 단순히 캐싱만을 위한 게 아니었고 여러 공격들을 어렵게 하기 위해 노력하고 있다.. 시간이 나고 DNS처리나 UDP에 관해 새로운 정보를 알게 되었을 때 다시 도전해볼 예정!
 <br>

[프로젝트 아이디어 출처 - 인프런 널널한 개발자님의 이해하면 인생이 바뀌는 네트워크 프로그래밍](https://www.inflearn.com/course/%EC%9D%B4%ED%95%B4%ED%95%98%EB%A9%B4-%EC%9D%B8%EC%83%9D%EC%9D%B4-%EB%B0%94%EB%80%8C%EB%8A%94-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D)
