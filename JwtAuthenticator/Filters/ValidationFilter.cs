using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace JwtAuthenticator.Filters;
public class ValidationFilter : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        foreach(var argument in context.ActionArguments.Values)
        {
            if (argument is null) continue;

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            if(context.HttpContext.RequestServices.GetService(validatorType) is IValidator validator)
            {
                var validatorContext = (IValidationContext)Activator.CreateInstance(
                    typeof(ValidationContext<>).MakeGenericType(argument.GetType()),
                    argument)!;

                var result = await validator.ValidateAsync(validatorContext, context.HttpContext.RequestAborted);

                if(!result.IsValid)
                {
                    var errors = result.Errors
                        .GroupBy(e => e.PropertyName)
                        .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray());

                    context.Result = new BadRequestObjectResult(new ValidationProblemDetails(errors));
                    return;
                }
            }
        }

        await next();
    }
}
