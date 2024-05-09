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
}