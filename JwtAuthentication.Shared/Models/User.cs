using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication.Shared.Models
{
    public class User
    {
        [Required]
        [EmailAddress]
        [Display(Name = "EmailAdress Adress")]
        public string EmailAdress { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [StringLength(80, ErrorMessage = "Doit etre entre {2} et {1} charactères", MinimumLength = 6)]
        [Display(Name = "Password")]
        public string Password { get; set; }

    }
}
