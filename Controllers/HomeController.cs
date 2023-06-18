using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using LoginReg.Models;


namespace LoginReg.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext db;

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;
        db = context;
    }

    public IActionResult Index()
    {
        return View("Index");
    }

    [HttpGet("Success")]

    public IActionResult Success()
    {
        return View("Success");
    }
    [HttpPost("register")]
    public IActionResult Register(User newUser)
    {
        if (!ModelState.IsValid)
        {
            return Index();
        }
        PasswordHasher<User> hashedPW = new PasswordHasher<User>();
        newUser.Password = hashedPW.HashPassword(newUser, newUser.Password);
        db.Users.Add(newUser);
        db.SaveChanges();

        HttpContext.Session.SetInt32("UUID", newUser.UserId);
        return RedirectToAction("Success");
    }

    [HttpPost("login")]

    public IActionResult Login(LoginUser loginUser)
    {
        if (!ModelState.IsValid)
        {
            return Index();
        }
        User? dbUser = db.Users.FirstOrDefault(user => user.Email == loginUser.LoginEmail);

        if (dbUser == null)
        {
            ModelState.AddModelError("LoginEmail", "does not match");
            return Index();
        }

        PasswordHasher<LoginUser> hashedPW = new PasswordHasher<LoginUser>();
        PasswordVerificationResult pwCompare = hashedPW.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);

        if(pwCompare == 0)
        {
            ModelState.AddModelError("LoginPassword", "does not match");
        }

        HttpContext.Session.SetInt32("UUID", dbUser.UserId);
        return RedirectToAction("Success");
    }

[HttpPost("logout")]
public IActionResult Logout()
{
    HttpContext.Session.Clear();
    return RedirectToAction("Index");
}

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
