using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Authorization.Model.Product;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace Authorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ProductController : ControllerBase
    {
        IConfiguration configuration;
        HttpClient client;

        public ProductController(IConfiguration config)
        {
            configuration = config;
            client = new HttpClient();
            client.BaseAddress = new Uri(configuration["Product"]);
        }

        [HttpGet]
        public IActionResult Get()
        {
            HttpResponseMessage response=null;
            try
            {
                response = client.GetAsync(client.BaseAddress + "api/Product").Result;
            }
            catch
            {
                return BadRequest("Micro Not working");
            }
            if (response.IsSuccessStatusCode)
            {
                string data = response.Content.ReadAsStringAsync().Result;
                return Ok(data);
            }
            return BadRequest();
        }

        [HttpGet("{Var}")]
        public IActionResult GetbyNameOrId(string Var)
        {
            HttpResponseMessage response = null;
            try
            {
                response = client.GetAsync(client.BaseAddress + "api/Product/" + Var).Result;
            }
            catch
            {
                return BadRequest("Micro Not working");
            }
            if (response.IsSuccessStatusCode)
            {
                string data = response.Content.ReadAsStringAsync().Result;
                return Ok(data);
            }
            return BadRequest();
        }
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] ProductItem sdata)
        {
            string data = JsonConvert.SerializeObject(sdata);
            StringContent content = new StringContent(data, Encoding.UTF8, "application/json");

            HttpResponseMessage response = null;
            try
            {
                response = client.PutAsync(client.BaseAddress + "api/Product/" + id, content).Result;
            }
            catch
            {
                return BadRequest("Micro Not working");
            }
            
            if (response.IsSuccessStatusCode)
            {
                return Ok();
            }
            return BadRequest();
        }

        [HttpPost]
        public IActionResult Post([FromBody] ProductItem obj)
        {
            string data = JsonConvert.SerializeObject(obj);
            StringContent content = new StringContent(data, Encoding.UTF8, "application/json");

            HttpResponseMessage response = null;
            try
            {
                response = client.PostAsync(client.BaseAddress + "api/Product/", content).Result;
            }
            catch
            {
                return BadRequest("Micro Not working");
            }
           
            if (response.IsSuccessStatusCode)
            {
                return Ok();
            }
            return BadRequest();
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            HttpResponseMessage response = null;
            try
            {
                response = client.DeleteAsync(client.BaseAddress + "api/Product/" + id).Result;
            }
            catch
            {
                return BadRequest("Micro Not working");
            }
            if (response.IsSuccessStatusCode)
                return Ok();
            return BadRequest();
        }
    }
}
