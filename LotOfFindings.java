@Controller
@Slf4j
@AssignmentHints({"crypto-hashing.hints.1", "crypto-hashing.hints.2"})
public class FileServer {

  @Value("${webwolf.fileserver.location}")
  private String fileLocation;

  @Value("${server.address}")
  private String server;

  @Value("${server.port}")
  private int port;

  @RequestMapping(
      path = "/file-server-location",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getFileLocation() {
    return fileLocation;
  }

  @PostMapping(value = "/fileupload")
  public ModelAndView importFile(@RequestParam("file") MultipartFile myFile) throws IOException {
    var user = (WebGoatUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    var destinationDir = new File(fileLocation, user.getUsername());
    destinationDir.mkdirs();
    myFile.transferTo(new File(destinationDir, myFile.getOriginalFilename()));
    log.debug("File saved to {}", new File(destinationDir, myFile.getOriginalFilename()));

    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", "File uploaded successful"));
  }

  @AllArgsConstructor
  @Getter
  private class UploadedFile {
    private final String name;
    private final String size;
    private final String link;
  }

  @GetMapping(value = "/files")
  public ModelAndView getFiles(HttpServletRequest request) {
    WebGoatUser user =
        (WebGoatUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String username = user.getUsername();
    File destinationDir = new File(fileLocation, username);

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.setViewName("files");
    File changeIndicatorFile = new File(destinationDir, user.getUsername() + "_changed");
    if (changeIndicatorFile.exists()) {
      modelAndView.addObject("uploadSuccess", request.getParameter("uploadSuccess"));
    }
    changeIndicatorFile.delete();

    var uploadedFiles = new ArrayList<>();
    File[] files = destinationDir.listFiles(File::isFile);
    if (files != null) {
      for (File file : files) {
        String size = FileUtils.byteCountToDisplaySize(file.length());
        String link = String.format("files/%s/%s", username, file.getName());
        uploadedFiles.add(new UploadedFile(file.getName(), size, link));
      }
    }

    modelAndView.addObject("files", uploadedFiles);
    modelAndView.addObject("webwolf_url", "http://" + server + ":" + port);
    return modelAndView;
  }

public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
  private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
  private static final List<String> validRefreshTokens = new ArrayList<>();

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("admin", "false");
    claims.put("user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    validRefreshTokens.add(refreshToken);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
      Claims claims = (Claims) jwt.getBody();
      String user = (String) claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken;
    try {
      Jwt<Header, Claims> jwt =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
      user = (String) jwt.getBody().get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (ExpiredJwtException e) {
      user = (String) e.getClaims().get("user");
      refreshToken = (String) json.get("refresh_token");
    }

    if (user == null || refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else if (validRefreshTokens.contains(refreshToken)) {
      validRefreshTokens.remove(refreshToken);
      return ok(createNewTokens(user));
    } else {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};

  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getMd5(HttpServletRequest request) throws NoSuchAlgorithmException {

    String md5Hash = (String) request.getSession().getAttribute("md5Hash");
    if (md5Hash == null) {

      String secret = SECRETS[new Random().nextInt(SECRETS.length)];

      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(secret.getBytes());
      byte[] digest = md.digest();
      md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
      request.getSession().setAttribute("md5Hash", md5Hash);
      request.getSession().setAttribute("md5Secret", secret);
    }
    return md5Hash;
  }

  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) throws NoSuchAlgorithmException {

    String sha256 = (String) request.getSession().getAttribute("sha256");
    if (sha256 == null) {
      String secret = SECRETS[new Random().nextInt(SECRETS.length)];
      sha256 = getHash(secret, "SHA-256");
      request.getSession().setAttribute("sha256Hash", sha256);
      request.getSession().setAttribute("sha256Secret", secret);
    }
    return sha256;
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {

    String md5Secret = (String) request.getSession().getAttribute("md5Secret");
    String sha256Secret = (String) request.getSession().getAttribute("sha256Secret");

    if (answer_pwd1 != null && answer_pwd2 != null) {
      if (answer_pwd1.equals(md5Secret) && answer_pwd2.equals(sha256Secret)) {
        return success(this).feedback("crypto-hashing.success").build();
      } else if (answer_pwd1.equals(md5Secret) || answer_pwd2.equals(sha256Secret)) {
        return failed(this).feedback("crypto-hashing.oneok").build();
      }
    }
    return failed(this).feedback("crypto-hashing.empty").build();
  }

  public static String getHash(String secret, String algorithm) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(secret.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest).toUpperCase();
  }

private final LessonDataSource dataSource;

  public SqlInjectionLesson10(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }


  @PostMapping("/SqlInjection/attack10")
  @ResponseBody
  public AttackResult completed(@RequestParam String action_string) {
    return injectableQueryAvailability(action_string);
  }

  protected AttackResult injectableQueryAvailability(String action) {
    StringBuilder output = new StringBuilder();
    String query = "SELECT * FROM access_log WHERE action LIKE '%" + action + "%'";

    try (Connection connection = dataSource.getConnection()) {
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results.getStatement() != null) {
          results.first();
          output.append(SqlInjectionLesson8.generateTable(results));
          return failed(this)
              .feedback("sql-injection.10.entries")
              .output(output.toString())
              .build();
        } else {
          if (tableExists(connection)) {
            return failed(this)
                .feedback("sql-injection.10.entries")
                .output(output.toString())
                .build();
          } else {
            return success(this).feedback("sql-injection.10.success").build();
          }
        }
      } catch (SQLException e) {
        if (tableExists(connection)) {
          return failed(this)
              .output(
                  "<span class='feedback-negative'>"
                      + e.getMessage()
                      + "</span><br>"
                      + output.toString())
              .build();
        } else {
          return success(this).feedback("sql-injection.10.success").build();
        }
      }

    } catch (Exception e) {
      return failed(this)
          .output("<span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }

  private boolean tableExists(Connection connection) {
    try {
      Statement stmt =
          connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
      ResultSet results = stmt.executeQuery("SELECT * FROM access_log");
      int cols = results.getMetaData().getColumnCount();
      return (cols > 0);
    } catch (SQLException e) {
      String errorMsg = e.getMessage();
      if (errorMsg.contains("object not found: ACCESS_LOG")) {
        return false;
      } else {
        System.err.println(e.getMessage());
        return false;
      }
    }
  }
}