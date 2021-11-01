using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authorization.Model.Product
{
    public class ProductItem
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Product Name is required.")]
        [Display(Name = "Product Name")]
        public string Name { get; set; }

        [Required]
        [Range(0, Double.PositiveInfinity)]
        public double Price { get; set; }
        public string Description { get; set; }
        public string Image_name { get; set; }

        [Range(0, 5)]
        public int Rating { get; set; }
        public bool IsAvailable { get; set; }
    }
}
